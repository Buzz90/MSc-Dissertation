def extract_payloads(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    extracted = []
    for line in lines:
        if "[PAYLOAD]" in line:
            payload = line.split("[PAYLOAD]", 1)[1].strip()
            extracted.append(payload)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for item in extracted:
            f.write(item + '\n')

    print(f"Extracted {len(extracted)} payloads from {input_file} to {output_file}.")

if __name__ == "__main__":
    extract_payloads("/Users/admin/Documents/MSc-Dissertation/kali/sqlmap_run.log", '/Users/admin/Documents/MSc-Dissertation/kali/output.txt')
