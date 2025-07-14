import json
import os

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch
import logging
logging.basicConfig(level=logging.INFO)


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
    max_new_tokens=8192,
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
You are a professional Solidity auditor and security analyst. Your task is to review the provided smart contract code and identify all potential vulnerabilities using known categories from the list below.

### KNOWN VULNERABILITY CLASSES:
{', '.join(KNOWN_VULNERABILITIES)}

### INSTRUCTIONS:
1. Analyze the entire contract carefully.
2. For each vulnerability found, return one object with the following fields:
   - "fromLine": starting line number of the issue
   - "toLine": ending line number of the issue
   - "vulnerabilityClass": choose from the known classes; if none match, use "Invalid Code" or "Other"
   - "description": explain why this is a vulnerability
   - "testCase": provide a minimal scenario showing how the vulnerability could be exploited
   - "priorArt": list at least one known exploit or incident related to this vulnerability type (e.g., "The DAO", "Parity Wallet Hack")
   - "fixedLines": show corrected lines of code that resolve the issue without introducing new ones
3. If no issues are found, return an empty array `[]`.
4. If the code is invalid or cannot be compiled, return exactly:
   [
     {{
       "fromLine": 1,
       "toLine": <total_lines>,
       "vulnerabilityClass": "Invalid Code",
       "description": "The contract contains syntax errors or undeclared identifiers and cannot be compiled."
     }}
   ]
5. Return only the JSON result inside triple backticks:

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


def generate_audit(source: str):
    full_prompt = f"{PROMPT}\n### SOLIDITY CONTRACT CODE:\n{source}"
    
    # Generate raw output from the model
    output = pipe(full_prompt, pad_token_id=tokenizer.eos_token_id)
    response = output[0]["generated_text"]

    return extract_json_from_response(response)

def extract_json_from_response(text: str) -> str:
    """Extracts JSON content enclosed in triple backticks (```json ... ```) or directly parses if no markdown."""
    try:
        # Try to find JSON inside ```json ... ``` blocks
        start_idx = text.find("```json")
        if start_idx != -1:
            end_idx = text.find("```", start_idx + 7)
            if end_idx == -1:
                end_idx = len(text)
            json_str = text[start_idx + 7:end_idx].strip()
        else:
            # Try to find any JSON array/object without markdown
            start_idx = text.find("[")
            if start_idx == -1:
                start_idx = text.find("{")
            if start_idx == -1:
                raise ValueError("No valid JSON or markdown block found")

            end_idx = text.rfind("]") + 1 if text.rfind("]") > start_idx else text.rfind("}") + 1
            if end_idx <= start_idx:
                raise ValueError("Mismatched JSON structure")

            json_str = text[start_idx:end_idx]

        # Parse and re-serialize to validate and format
        json_obj = json.loads(json_str)
        return json.dumps(json_obj, indent=2)

    except Exception as e:
        logging.error(f"Failed to extract JSON: {e}")
        return json.dumps([
            {
                "fromLine": 1,
                "toLine": len(text.splitlines()),
                "vulnerabilityClass": "Invalid Code",
                "description": "Model returned invalid JSON or non-parsable output.",
                "priorArt": [],
                "fixedLines": "Ensure the model returns valid JSON within ```json ... ``` blocks."
            }
        ], indent=2)


REQUIRED_KEYS = {
    "fromLine",
    "toLine",
    "vulnerabilityClass",
    "description",
}
INT_KEYS = ("fromLine", "toLine")


def try_prepare_result(result) -> list[dict] | None:
    logging.info("Raw result to prepare:")
    logging.info(result)

    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode failed: {str(e)}")
            return None

    # At this point, result should be a list of dicts
    if not isinstance(result, list):
        if isinstance(result, dict) and len(result) == 1 and isinstance(list(result.values())[0], list):
            result = list(result.values())[0]
        else:
            result = [result]

    prepared = []

    for idx, item in enumerate(result):
        if not isinstance(item, dict):
            logging.warning(f"Item at index {idx} is not a dict: {item}")
            continue

        # Ensure required keys exist
        for key in REQUIRED_KEYS:
            if key not in item:
                logging.warning(f"Missing required key '{key}' in item: {item}")
                return None

        cleared = {k: item[k] for k in REQUIRED_KEYS}

        # Optional keys
        if "priorArt" in item and isinstance(item["priorArt"], list):
            cleared["priorArt"] = item["priorArt"]
        if "fixedLines" in item and isinstance(item["fixedLines"], str):
            cleared["fixedLines"] = item["fixedLines"]
        if "testCase" in item and isinstance(item["testCase"], str):
            cleared["testCase"] = item["testCase"]

        # Validate int keys
        for k in INT_KEYS:
            val = item[k]
            if isinstance(val, int):
                cleared[k] = val
            elif isinstance(val, str) and val.isdigit():
                cleared[k] = int(val)
            else:
                logging.warning(f"Invalid value for key '{k}': {val}, type: {type(val)}")
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


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}

@app.get("/test-audit")
async def test_audit():
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    contract_code = SOLIDITY_CONTRACT
    while tries > 0:
        result = generate_audit(contract_code)
        print("==================================================================")
        print(result)
        print("==================================================================")
        result = try_prepare_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Unable to prepare audit")
    return result


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5001")))
