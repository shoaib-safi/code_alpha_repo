import json
import matplotlib.pyplot as plt
from collections import Counter

# Load eve.json log file
with open('../logs/eve.json', 'r') as f:
    events = [json.loads(line) for line in f]

# Filter alerts and extract signatures
signatures = [event['alert']['signature'] for event in events if 'alert' in event]

# Count occurrences of each signature
counter = Counter(signatures)

# Plot the results
plt.figure(figsize=(10, 6))
plt.bar(counter.keys(), counter.values(), color='blue')
plt.xticks(rotation=45, ha="right")
plt.title("Detected Network Attacks")
plt.ylabel("Occurrences")
plt.tight_layout()

# Save as an image
plt.savefig("../reports/detected_attacks.png")

# Save summary as CSV
with open('../reports/summary.csv', 'w') as f:
    f.write("Signature,Count\n")
    for sig, count in counter.items():
        f.write(f"{sig},{count}\n")

print("Visualization and summary report generated successfully.")
