import csv
import json

def csv_to_jsonl(input_csv, output_jsonl):
    with open(input_csv, 'r') as csv_file, open(output_jsonl, 'w') as jsonl_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            payload, label = row['payload'], row['label']
            conversation = {
                "messages": [
                    {"role": "system", "content": "You are an expert in SQL injection payloads."},
                    {"role": "user", "content": "generate 50 payload that bypasses login authentication."},
                    {"role": "assistant", "content": payload}
                ]
            }
            jsonl_file.write(json.dumps(conversation) + '\n')
    print(f"[+] Saved JSONL to {output_jsonl}")