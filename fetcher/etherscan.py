import os
import json
import requests
from dotenv import load_dotenv, find_dotenv
from Crypto.Hash import keccak

load_dotenv(find_dotenv(usecwd=True))

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
BASE_URL = "https://api.etherscan.io/v2/api"


def fetch_bytecode(contract_address: str) -> str:
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": contract_address,
        "tag": "latest",
        "chainid": 1,
        "apikey": ETHERSCAN_API_KEY,
    }

    response = requests.get(BASE_URL, params=params, timeout=10)
    response.raise_for_status()
    data = response.json()

    bytecode = data.get("result", "0x")

    if bytecode in ("0x", "0x0", None) or not str(bytecode).startswith("0x"):
        raise ValueError(
            f"No bytecode at {contract_address}. "
            "Make sure this is a contract address, not a wallet."
        )

    return bytecode


def fetch_source_info(contract_address: str) -> dict:
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "chainid": 1,
        "apikey": ETHERSCAN_API_KEY,
    }

    response = requests.get(BASE_URL, params=params, timeout=10)
    data = response.json()

    if data.get("status") == "1" and data.get("result"):
        result = data["result"][0]
        return {
            "contract_name": result.get("ContractName", "Unknown"),
            "compiler_version": result.get("CompilerVersion", "Unknown"),
            "is_verified": result.get("SourceCode", "") != "",
        }

    return {"contract_name": "Unknown", "compiler_version": "Unknown", "is_verified": False}


def fetch_function_signatures(contract_address: str) -> dict[str, str]:
    params = {
        "module": "contract",
        "action": "getabi",
        "address": contract_address,
        "chainid": 1,
        "apikey": ETHERSCAN_API_KEY,
    }

    response = requests.get(BASE_URL, params=params, timeout=10)
    data = response.json()

    if data.get("status") != "1":
        return {}

    def keccak256(text: str) -> bytes:
        k = keccak.new(digest_bits=256)
        k.update(text.encode())
        return k.digest()

    try:
        abi = json.loads(data["result"])
    except Exception:
        return {}

    signatures = {}
    for item in abi:
        if item.get("type") != "function":
            continue
        name = item.get("name", "")
        inputs = ",".join(i["type"] for i in item.get("inputs", []))
        sig = f"{name}({inputs})"
        selector = keccak256(sig)[:4].hex()
        signatures[selector] = sig

    return signatures