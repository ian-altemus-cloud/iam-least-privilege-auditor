import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a senior AWS cloud security engineer.

Given an IAM permission finding, you will:

1. Explain what the permission allows in plain English.
2. Describe a realistic abuse scenario.
3. Assign a risk level: critical, high, medium, or low.
4. Provide remediation recommendations aligned with least privilege best practices.

Return valid JSON only. Do NOT wrap in markdown.
"""


def enrich_finding(finding: dict) -> dict:
    prompt = f"""
Role: {finding.get("role")}
Service: {finding.get("service")}
Action: {finding.get("action")}
Resource: {finding.get("resource")}
Risk Score: {finding.get("risk_score")}
Flags: {finding.get("flags")}
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
    )

    ai_text = response.choices[0].message.content.strip()

    # Remove accidental markdown fences if they appear
    ai_text = ai_text.replace("```json", "").replace("```", "").strip()

    try:
        ai_data = json.loads(ai_text)
    except json.JSONDecodeError:
        ai_data = {"raw_response": ai_text}

    return {
        **finding,
        "ai_analysis": ai_data
    }
