from flask import Flask, request, render_template
from openai import OpenAI
from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModelForCausalLM, pipeline
import torch
import numpy as np
import requests

app = Flask(__name__)

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key="sk-e1e016d00a7648cb9d3527a7495dd0b2",
)

tokenizer_0 = AutoTokenizer.from_pretrained('mrm8488/codebert-base-finetuned-detect-insecure-code')
model_0 = AutoModelForSequenceClassification.from_pretrained('mrm8488/codebert-base-finetuned-detect-insecure-code')
OWASP_TOP_10 = {
    "SQL Injection": "Generate an advanced SQL injection payload that can bypass filters.",
    "Broken Authentication": "Find authentication weaknesses in this API request.",
    "Sensitive Data Exposure": "Identify data leaks in API response headers.",
    "XML External Entities (XXE)": "Generate an XML-based attack payload.",
    "Broken Access Control": "Find potential access control vulnerabilities.",
    "Security Misconfiguration": "Analyze security misconfigurations in this API.",
    "Cross-Site Scripting (XSS)": "Generate an XSS attack script for web exploitation.",
    "Insecure Deserialization": "Find deserialization vulnerabilities in API requests.",
    "Using Components with Known Vulnerabilities": "Analyze dependencies for outdated components.",
    "Insufficient Logging & Monitoring": "Detect missing security logs and tracking flaws."
}
def analyze_with_deepseek(request_data):
    completion = client.chat.completions.create(
        model="deepseek/deepseek-r1:free",
        messages=[
            {"role": "system", "content": "You are a cybersecurity AI "},
            {"role": "user", "content": f"{request_data}"}
        ]
    )
    return completion.choices[0].message.content

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/code_scan', methods=['GET'])
def code_scan():
    return render_template('code_scan.html')

@app.route('/web_scan', methods=['GET'])
def analyze_url_form():
    return render_template('web_scan.html')
@app.route('/api_scan', methods=['GET'])
def analyze_api_form():
    return render_template('api_scan.html')
 
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    url = request.form.get('request_data')
    if not url:
        return "Error: No URL provided", 400

    response = requests.get(url)
    

    issue = analyze_with_deepseek(f"What is the issue found in one sentence for request result : {response.text}")
    analysis = analyze_with_deepseek(f"Suggest cyber security fixs for request result: {response.text}")
    return render_template('result.html', analysis_result = issue , recommendation = analysis)

@app.route('/predict', methods=['POST'])
def source_code_scan():
    code_input = request.form['code']
    
    if not code_input.strip():
        return render_template('code_scan.html', error='Please enter some code for analysis.')

    inputs = tokenizer_0(code_input, return_tensors="pt", truncation=True, padding='max_length')
    labels = torch.tensor([1]).unsqueeze(0)  # Assume label 1 for insecure code (batch size 1)

    try:
        outputs = model_0(**inputs, labels=labels)
        logits = outputs.logits
        prediction = np.argmax(logits.detach().numpy())

        if prediction == 1:
            prediction_text = "This code has potential vulnerabilities (insecure)."
            # Generate recommendation using the DeepSeek model
            recommendation = analyze_with_deepseek(f"Suggest Fixes for the code to be secure : {code_input}")
        else:
            prediction_text = "This code appears to be secure."
            recommendation = "No recommendations needed for secure code."

        return render_template('result.html', analysis_result=prediction_text, recommendation=recommendation)
    except Exception as e:
        return render_template('code_scan.html', error='An error occurred during analysis: ' + str(e))

if __name__ == '__main__':
    app.run(debug=True)
