import json
import os

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch

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
    max_new_tokens=4096,
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


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5001")))
