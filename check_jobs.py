import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for job in data.get('jobs', []):
    name = job.get('name', 'unknown')
    labels = job.get('labels', [])
    label = labels[0] if labels else '?'
    status = job.get('status', 'unknown')
    conclusion = job.get('conclusion', 'unknown')
    print(f'{name} ({label}): {status} / {conclusion}')
    if job.get('conclusion') == 'failure':
        for step in job.get('steps', []):
            if step.get('conclusion') == 'failure':
                print(f'  FAILED STEP: {step["name"]}')