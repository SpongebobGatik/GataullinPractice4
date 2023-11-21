import requests
import json

dimensions_order = input("Введите порядок измерений, разделенных пробелами (TimeInterval, URL, SourceIP): ").split()

response = requests.post('http://localhost:5001/report', json={"Dimensions": dimensions_order})

print(json.dumps(response.json(), indent=4, ensure_ascii=False))
