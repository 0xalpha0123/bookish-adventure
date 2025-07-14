import json
import os
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch
import uvicorn
import requests

app = FastAPI()

# Load tokenizer and model from local directory containing .safetensors files
model_name_or_path = "./DeepSeek-R1-Distill-Qwen-7B"  # Update this path accordingly
tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
model = AutoModelForCausalLM.from_pretrained(
    model_name_or_path,
    torch_dtype=torch.bfloat16,  # Or torch.float16 depending on your GPU RAM
    device_map="auto"
)

# Create a text generation pipeline
pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=32768,
    do_sample=True,
    temperature=0.7,
    top_p=0.95,
    repetition_penalty=1.1
)

ROLE_SYSTEM = "system"
ROLE_ASSISTANT = "assistant"
ROLE_USER = "user"
KNOWN_VULNERABILITIES = [
    "Reentrancy", "Gas griefing", "Oracle manipulation", "Bad randomness", 
    "Unexpected privilege grants", "Forced reception", "Integer overflow/underflow",
    "Race condition", "Unguarded function", "Inefficient storage key",
    "Front-running potential", "Miner manipulation", "Storage collision",
    "Signature replay", "Unsafe operation", "Invalid code"
]

PROMPT = f"""
You are a professional Solidity smart contract auditor assisting in identifying and analyzing potential vulnerabilities in a given contract.
Given the Solidity contract code with line numbers, analyze it thoroughly and generate a detailed audit report in strict JSON format as specified below. 
When identifying and classifying security issues, consider the following known vulnerability types:
{', '.join(KNOWN_VULNERABILITIES)}
Your analysis must include:
- Precise line numbers (`fromLine`, `toLine`) where each vulnerability exists.
- A clear classification from the list above (or 'Invalid Code' if applicable).
- A concise but thorough description of why the code is vulnerable.
- A minimal test case or exploit scenario that demonstrates how the vulnerability could be triggered.
- Prior Art: Known real-world exploits or incidents related to this type of vulnerability.
- Suggested fixed lines of code that resolve the issue without introducing new ones.
If the entire code cannot be compiled or analyzed meaningfully:
- Return a single entry with:
    {{
        "fromLine": 1,
        "toLine": Total number of lines in the code,
        "vulnerabilityClass": "Invalid Code",
        "description": "The contract contains syntax errors or undeclared identifiers and cannot be compiled."
    }}
Output Format:
[
    {{
        "fromLine": integer,
        "toLine": integer,
        "vulnerabilityClass": string,
        "testCase": string,
        "description": string,
        "priorArt": [string],
        "fixedLines": string
    }}
]
""".strip()

def generate_audit(source: str):
    full_prompt = f"{PROMPT}\n\n### SOLIDITY CONTRACT CODE:\n{source}"
    output = pipe(full_prompt, pad_token_id=tokenizer.eos_token_id)
    response = output[0]["generated_text"]
    return response

REQUIRED_KEYS = {
    "fromLine",
    "toLine",
    "vulnerabilityClass",
    "description",
}
INT_KEYS = ("fromLine", "toLine")

def try_prepare_result(result) -> list[dict] | None:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return None
    if isinstance(result, dict):
        if (
            len(result) == 1
            and isinstance(list(result.values())[0], list)
            and all(isinstance(item, dict) for item in list(result.values())[0])
        ):
            result = list(result.values())[0]
        else:
            result = [result]
    prepared = []
    for item in result:
        for key in REQUIRED_KEYS:
            if key not in item:
                return None
        cleared = {k: item[k] for k in REQUIRED_KEYS}
        if (
            "priorArt" in item
            and isinstance(item["priorArt"], list)
            and all(isinstance(x, str) for x in item["priorArt"])
        ):
            cleared["priorArt"] = item["priorArt"]
        if "fixedLines" in item and isinstance(item["fixedLines"], str):
            cleared["fixedLines"] = item["fixedLines"]
        if "testCase" in item and isinstance(item["testCase"], str):
            cleared["testCase"] = item["testCase"]
        for k in INT_KEYS:
            if isinstance(cleared[k], int) or (
                isinstance(item[k], str) and item[k].isdigit()
            ):
                cleared[k] = int(cleared[k])
            else:
                return None
        prepared.append(cleared)
    return prepared


@app.post("/submit")
async def submit(request: Request):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    contract_code = (await request.body()).decode("utf-8")
    while tries > 0:
        result = generate_audit(contract_code)
        result = try_prepare_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Unable to prepare audit")
    return result


@app.post("/forward")
async def forward(request: Request):
    return await submit(request)


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


# 🧪 Test Endpoint — Submit hardcoded contract
SOLIDITY_CONTRACT = '''
pragma solidity ^0.8.0;
contract VestingManager {
    enum HolderStatus {
        INACTIVE,
        ACTIVE,
        TERMINATED
    }
    struct VestingHolder {
        uint256 startTime;
        uint256 endTime;
        uint256 totalAmount;
        uint256 releasedAmount;
        HolderStatus status;
    }
    address public owner;
    uint256 public totalVestedTokens;
    uint256 public vestingDuration;
    mapping(address => VestingHolder) private _vestingHolders;
    mapping(address => address) private _holderToEscrow;
    event VestingInitiated(address indexed holder, uint256 amount, uint256 duration);
    event VestingTerminated(address indexed holder, uint256 vestedAmount);
    event EscrowCreated(address indexed holder, address escrowAddress);
    modifier onlyOwner() {
        require(msg.sender == owner, 'Only owner can call this function');
        _;
    }
    constructor(uint256 _vestingDuration) {
        owner = msg.sender;
        vestingDuration = _vestingDuration;
        totalVestedTokens = 0;
    }
    function createVestingSchedule(address holder, uint256 amount) external onlyOwner {
        require(holder != address(0), 'Invalid holder address');
        require(amount > 0, 'Amount must be greater than zero');
        require(_vestingHolders[holder].status == HolderStatus.INACTIVE, 'Holder already has active vesting');
        address escrowAddress = address(new CoreEscrow(holder, amount));
        _holderToEscrow[holder] = escrowAddress;
        _vestingHolders[holder] = VestingHolder({startTime: block.timestamp, endTime: block.timestamp + vestingDuration, totalAmount: amount, releasedAmount: 0, status: HolderStatus.ACTIVE});
        totalVestedTokens += amount;
        emit VestingInitiated(holder, amount, vestingDuration);
        emit EscrowCreated(holder, escrowAddress);
    }
    function calculateVestedAmount(address holder) public view returns (uint256) {
        VestingHolder memory holderInfo = _vestingHolders[holder];
        if (holderInfo.status != HolderStatus.ACTIVE) {
            return holderInfo.releasedAmount;
        }
        if (block.timestamp >= holderInfo.endTime) {
            return holderInfo.totalAmount;
        }
        uint256 timeElapsed = block.timestamp - holderInfo.startTime;
        uint256 totalVestingTime = holderInfo.endTime - holderInfo.startTime;
        return (holderInfo.totalAmount * timeElapsed) / totalVestingTime;
    }
    function terminateEscrow(address holder) external onlyOwner {
        require(_vestingHolders[holder].status == HolderStatus.ACTIVE, 'Cannot stop vesting for a non active holder');
        CoreEscrow(_holderToEscrow[holder]).cancelVesting(calculateVestedAmount(holder));
    }
    function getHolderInfo(address holder) external view returns (VestingHolder memory) {
        return _vestingHolders[holder];
    }
    function updateVestingDuration(uint256 newDuration) external onlyOwner {
        require(newDuration > 0, 'Duration must be greater than zero');
        vestingDuration = newDuration;
    }
}
contract CoreEscrow {
    address public beneficiary;
    address public manager;
    uint256 public totalAmount;
    uint256 public releasedAmount;
    bool public isCancelled;
    constructor(address _beneficiary, uint256 _totalAmount) {
        beneficiary = _beneficiary;
        manager = msg.sender;
        totalAmount = _totalAmount;
        releasedAmount = 0;
        isCancelled = false;
    }
    modifier onlyManager() {
        require(msg.sender == manager, 'Only manager can call this function');
        _;
    }
    function cancelVesting(uint256 vestedAmount) external onlyManager {
        require(!isCancelled, 'Vesting already cancelled');
        require(vestedAmount <= totalAmount, 'Vested amount exceeds total amount');
        isCancelled = true;
        releasedAmount = vestedAmount;
    }
}
'''

@app.get("/test-audit")
async def test_audit():
    """
    Submits a hardcoded Solidity contract to the audit endpoint and returns the result.
    """
    app_url = "http://localhost:5001/submit"
    headers = {"Content-Type": "application/json"}
    response = requests.post(app_url, data=SOLIDITY_CONTRACT.encode('utf-8'), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail="Audit failed")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5001")))
