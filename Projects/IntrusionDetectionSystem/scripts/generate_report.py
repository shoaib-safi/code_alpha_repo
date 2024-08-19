import pandas as pd
from jinja2 import Template

# Load the summary CSV
df = pd.read_csv('../reports/summary.csv')

# Load the HTML template
template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detected Attacks Report</title>
</head>
<body>
    <h1>Network Intrusion Detection Report</h1>
    <h2>Summary of Detected Attacks</h2>
    <img src="detected_attacks.png" alt="Detected Attacks" style="width:100%;max-width:600px;">
    <h2>Details</h2>
    <table border="1">
        <thead>
            <tr>
                <th>Signature</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            {% for index, row in data.iterrows() %}
            <tr>
                <td>{{ row['Signature'] }}</td>
                <td>{{ row['Count'] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
''')

# Render the HTML report
html_report = template.render(data=df)

# Save the report
with open('../reports/detected_attacks.html', 'w') as f:
    f.write(html_report)

print("HTML report generated successfully.")
