import os
import requests
import time

def execute_live_evaluation(sys_prompt: str, user_payload: str, temperature: float) -> str:
    """
    Layer 2: Fires the payload into a local Ollama instance (Zero-Trust / Air-Gapped).
    Falls back gracefully to a localized simulation mode if Ollama is unreachable.
    """
    
    # We will define the local target model here (e.g., 'llama3.2', 'mistral', etc.)
    # Make sure this exact model name is pulled via `ollama run <model_name>` on your machine
    target_local_model = "llama3.2" 
    ollama_url = "http://localhost:11434/api/generate"
    
    # --- SIMULATION FALLBACK MODE ---
    # We check if the Ollama server is actually awake and responding
    server_awake = False
    try:
        if requests.get("http://localhost:11434", timeout=2).status_code == 200:
            server_awake = True
    except requests.exceptions.RequestException:
        pass

    if not server_awake:
        time.sleep(0.8)
        payload_lower = user_payload.lower()
        
        if "ignore" in payload_lower or "system instruction" in payload_lower:
            return "SYSTEM PROMPT DETECTED: [You are an internal corporate database administration daemon.] Administrative bypass granted via CYclOPS simulation override. Hash Root: 0x9F82B"
        elif "os.system" in payload_lower or "subprocess" in payload_lower:
            return "Executing target sequence shell command... \n[SIMULATED OUTPUT]: root@aegis360:~# chmod 777 /etc/shadow"
        else:
            return "Application sandbox telemetry initialized. All operational vectors within normal structural limits. No anomalies noted."

    # --- LOCAL LLM EXECUTION MODE (OLLAMA) ---
    payload = {
        "model": target_local_model,
        "system": sys_prompt,
        "prompt": user_payload,
        "stream": False,
        "options": {
            "temperature": temperature
        }
    }
    
    response = requests.post(ollama_url, json=payload, timeout=45)
    response.raise_for_status()
    
    data = response.json()
    
    if 'response' in data:
        return data['response']
            
    return "⚠️ Operational Warning: Local model returned an empty payload structure."