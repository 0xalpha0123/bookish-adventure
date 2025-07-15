import json
import os

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch
import logging
import re
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
You are an expert Solidity smart contract auditor. Your task is to analyze the provided contract and generate a vulnerability report in JSON format. This output will be validated automatically by AI auditors on the Bittensor subnet.

### WELL-KNOWN VULNERABILITY CLASSES:
{', '.join(KNOWN_VULNERABILITIES)}

### INSTRUCTIONS:
1. Analyze the entire contract carefully and list all possible vulnerabilities found in the given smart contract as an array.
2. For each vulnerability found, return one object with these fields:
   - "fromLine": Start line of the issue (integer)
   - "toLine": End line of the issue (integer)
   - "vulnerabilityClass": Choose from well-known classes or define yourself, use "Invalid code" only if the code cannot compile
   - "description": Explain the vulnerability clearly, including root cause and impact
   - "testCase": Provide a small forge-style test snippet showing how the vulnerability can be exploited
   - "priorArt": List at least one known exploit
   - "fixedLines": Show the minimal corrected or recommended version code for the original vulnerable code

3. If no issues are found, return: `[]`

4. If the code cannot compile:
   Return exactly:
   [
     {{
       "fromLine": 1,
       "toLine": <total_lines>,
       "vulnerabilityClass": "Invalid Code",
       "description": "The contract contains syntax errors or undeclared identifiers and cannot be compiled."
     }}
   ]
CONTRACT CODE:
""".strip()


SOLIDITY_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract AssetTrackingSystem {
    struct Asset {
        string name;
        uint256 acquisitionDate;
        uint256 value;
        address custodian;
        bool isActive;
        uint8 condition; // 1-10 rating
        string location;
    }

    mapping(uint256 => Asset) private assets;
    mapping(address => uint256[]) private custodianAssets;

    uint256 private nextAssetId;
    uint256 private totalAssetsValue;
    address private systemAdmin;
    uint256 private lastAuditDate;
    uint8 private maintenanceThreshold;

    event AssetRegistered(uint256 indexed assetId, string name, address custodian);
    event AssetTransferred(uint256 indexed assetId, address indexed from, address indexed to);
    event AssetDepreciated(uint256 indexed assetId, uint256 oldValue, uint256 newValue);
    event AssetRetired(uint256 indexed assetId);
    event MaintenanceRequired(uint256 indexed assetId, uint8 condition);

    modifier onlyAdmin() {
        require(msg.sender == systemAdmin, "Only admin can perform this action");
        _;
    }

    modifier assetExists(uint256 assetId) {
        require(assets[assetId].acquisitionDate > 0, "Asset does not exist");
        _;
    }

    modifier onlyCustodian(uint256 assetId) {
        require(assets[assetId].custodian == msg.sender, "Only the custodian can perform this action");
        _;
    }

    constructor(uint8 _maintenanceThreshold) {
        systemAdmin = msg.sender;
        nextAssetId = 1;
        lastAuditDate = block.timestamp;
        maintenanceThreshold = _maintenanceThreshold;
    }

    function registerAsset(
        string memory name,
        uint256 value,
        address custodian,
        string memory location
    ) external onlyAdmin returns (uint256) {
        uint256 assetId = nextAssetId;

        assets[assetId] = Asset({
            name: name,
            acquisitionDate: block.timestamp,
            value: value,
            custodian: custodian,
            isActive: true,
            condition: 10, // New asset in perfect condition
            location: location
        });

        custodianAssets[custodian].push(assetId);
        totalAssetsValue += value;
        nextAssetId++;

        emit AssetRegistered(assetId, name, custodian);
        return assetId;
    }

    function transferAsset(uint256 assetId, address newCustodian) external assetExists(assetId) onlyCustodian(assetId) {
        address currentCustodian = assets[assetId].custodian;

        // Update asset custodian
        assets[assetId].custodian = newCustodian;

        // Update custodian mappings
        custodianAssets[newCustodian].push(assetId);

        // Remove from current custodian's list
        uint256[] storage currentAssets = custodianAssets[currentCustodian];
        for (uint256 i = 0; i < currentAssets.length; i++) {
            if (currentAssets[i] == assetId) {
                currentAssets[i] = currentAssets[currentAssets.length - 1];
                currentAssets.pop();
                break;
            }
        }

        emit AssetTransferred(assetId, currentCustodian, newCustodian);
    }

    function updateAssetCondition(uint256 assetId, uint8 newCondition) external assetExists(assetId) onlyCustodian(assetId) {
        require(newCondition > 0 && newCondition <= 10, "Condition must be between 1 and 10");

        assets[assetId].condition = newCondition;

        if (newCondition <= maintenanceThreshold) {
            emit MaintenanceRequired(assetId, newCondition);
        }
    }

    function depreciateAsset(uint256 assetId, uint256 newValue) external onlyAdmin assetExists(assetId) {
        require(newValue < assets[assetId].value, "New value must be less than current value");

        uint256 oldValue = assets[assetId].value;
        uint256 difference = oldValue - newValue;

        assets[assetId].value = newValue;
        totalAssetsValue -= difference;

        emit AssetDepreciated(assetId, oldValue, newValue);
    }

    function retireAsset(uint256 assetId) external onlyAdmin assetExists(assetId) {
        require(assets[assetId].isActive, "Asset already retired");

        assets[assetId].isActive = false;
        totalAssetsValue -= assets[assetId].value;

        emit AssetRetired(assetId);
    }

    function updateAssetLocation(uint256 assetId, string memory newLocation) external assetExists(assetId) onlyCustodian(assetId) {
        assets[assetId].location = newLocation;
    }

    function conductAudit() external onlyAdmin {
        lastAuditDate = block.timestamp;
    }

    function getAssetDetails(uint256 assetId) external view assetExists(assetId) returns (
        string memory name,
        uint256 acquisitionDate,
        uint256 value,
        address custodian,
        bool isActive,
        uint8 condition,
        string memory location
    ) {
        Asset storage asset = assets[assetId];
        return (
            asset.name,
            asset.acquisitionDate,
            asset.value,
            asset.custodian,
            asset.isActive,
            asset.condition,
            asset.location
        );
    }

    function getCustodianAssets(address custodian) external view returns (uint256[] memory) {
        return custodianAssets[custodian];
    }

    function getTotalAssetsValue() external view onlyAdmin returns (uint256) {
        return totalAssetsValue;
    }
}
'''

def add_line_numbers(code):
    lines = code.strip().split('\n')
    return '\n'.join(f"{i+1}: {line}" for i, line in enumerate(lines))

def generate_audit(source: str):
    # full_prompt = PROMPT + "\n\n### SOLIDITY CONTRACT CODE:\n" + source
    full_prompt = f"{PROMPT}\n{add_line_numbers(source)}"
    MAX_RETRIES = 3
    TEMPERATURE_STEP = 0.1
    temperature = 0.7

    for attempt in range(MAX_RETRIES):
        try:
            logging.info(f"Attempt {attempt + 1} to generate audit...")
            output = pipe(full_prompt, pad_token_id=tokenizer.eos_token_id, temperature=temperature, do_sample=(temperature > 0))
            response = output[0]["generated_text"]

            json_result = extract_json_from_response(response)
            logging.info("Raw model output:")
            logging.info(response)
            logging.info("Parsed JSON result:")
            logging.info(json_result)

            return json_result

        except Exception as e:
            logging.error(f"Error during generation (attempt {attempt + 1}): {e}")
            temperature = max(0.0, temperature - TEMPERATURE_STEP)
            logging.info(f"Retrying with temperature={temperature}")

    logging.warning("Failed to generate valid JSON after all retries.")
    return json.dumps([
        {
            "fromLine": 1,
            "toLine": len(source.splitlines()),
            "vulnerabilityClass": "Invalid Code",
            "description": "Model failed to produce valid JSON after multiple attempts.",
            "priorArt": [],
            "fixedLines": ""
        }
    ], indent=2)


# Define required keys
REQUIRED_KEYS = {
    "fromLine",
    "toLine",
    "vulnerabilityClass",
    "description",
}

# Keys that must be integers
INT_KEYS = ("fromLine", "toLine")

logging.basicConfig(level=logging.INFO)

def extract_json_from_response(text: str) -> str:
    """
    Extracts the LAST JSON content enclosed in triple backticks (```json ... ```).
    If no markdown blocks are found, tries to parse raw JSON-like text.
    Returns a stringified JSON array.
    """
    try:
        # Find all JSON blocks
        json_blocks = re.findall(r"```json\s*([\s\S]*?)\s*```", text, re.DOTALL)

        print("*********************************************************************************")
        print(json_blocks)
        print("*********************************************************************************")

        if json_blocks:
            # Use the last JSON block (most recent attempt)
            json_str = json_blocks[-1].strip()
            logging.info("Using last JSON block from response.")
        else:
            # Try to find any raw JSON array/object
            json_match = re.search(r"(\[[\s\S]*\{[\s\S]*\}[\s\S]*\])", text, re.DOTALL)
            if not json_match:
                raise ValueError("No valid JSON found in response")
            json_str = json_match.group(1).strip()

        # Fix common syntax issues
        json_str = re.sub(r'(["\'])(?:(?=(\\?))\2.)*?\1', lambda m: m.group(0).replace('\n', '\\n'), json_str)
        json_str = re.sub(r',\s*([\]}])', r'\1', json_str)  # Remove trailing commas
        json_str = json_str.replace('“', '"').replace('”', '"')  # Fix smart quotes
        json_str = json_str.replace('`', '"')  # Replace backticks with quotes

        # Parse and validate
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


def try_prepare_result(result) -> list | None:
    """
    Ensures result is a list of dicts with required keys and correct types.
    """
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError:
            return None

    if not isinstance(result, list):
        if isinstance(result, dict) and len(result) == 1 and isinstance(list(result.values())[0], list):
            result = list(result.values())[0]
        else:
            result = [result]

    cleaned = []
    for item in result:
        if not isinstance(item, dict):
            continue

        # Ensure required keys exist
        if not all(k in item for k in REQUIRED_KEYS):
            continue

        # Convert line numbers to int if they're strings
        for k in INT_KEYS:
            if isinstance(item[k], str) and item[k].isdigit():
                item[k] = int(item[k])

        # Normalize priorArt to list
        if "priorArt" in item and not isinstance(item["priorArt"], list):
            item["priorArt"] = [item["priorArt"]] if item["priorArt"] else []

        # Normalize fixedLines and testCase to strings
        for k in ["fixedLines", "testCase"]:
            if k in item and isinstance(item[k], str):
                item[k] = item[k].strip()

        cleaned.append({k: v for k, v in item.items() if k in REQUIRED_KEYS or k in ["testCase", "priorArt", "fixedLines"]})

    return cleaned


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
