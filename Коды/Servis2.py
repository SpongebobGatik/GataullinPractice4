import string
from flask import Flask, request, jsonify
import datetime
import socket
import requests
import json

# Класс для сбора и обработки статистики.
class Statistics:
    # Инициализация класса с запросом IP-адреса и порта сервера.
    def __init__(self):
        self.SERVER_IP, self.SERVER_PORT = input("Введите IP-адрес и порт сервера СУБД (формат: myip:myport): ").split(':')
        self.SERVER_PORT = int(self.SERVER_PORT)
        # Словари для хранения статистики.
        self.statistics1 = {}
        self.statistics2 = {}
        self.statistics3 = {}
        self.statistics4 = {}
        self.statistics5 = {}
        self.statistics6 = {}
        self.count_tik = 0 # Счетчик для итерации данных.
        
    # Метод для загрузки и обновления статистики.
    def load(self):
        # Очистка словарей перед загрузкой новых данных.
        self.statistics1.clear()
        self.statistics2.clear()
        self.statistics3.clear()
        self.statistics4.clear()
        self.statistics5.clear()
        self.statistics6.clear()
        self.count_tik = 0 # Сброс счетчика.
        last_ip = ""  # Последний известный IP-адрес.
        last_url = ""  # Последний известный URL.
        # Бесконечный цикл для получения данных до прерывания.
        while True:
            self.count_tik = self.count_tik + 1
            # Создание сокета для подключения к серверу.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((self.SERVER_IP, self.SERVER_PORT))
                except Exception as e:
                    print (f'Не удалось подключиться к серверу: {str(e)}')
                # Отправка запроса на сервер для получения IP-адреса.
                s.sendall(f'--file urls.data --query HGET ip {self.count_tik}'.encode())
                ip = s.recv(1024).decode()
                ip = ip.replace('\n', '').replace('\r', '')
                if ip == "Error.":
                    print ('Error.')
                if ip == "-> False":
                    ip = last_ip # Если данных нет, используется последний известный IP.
                last_ip = ip
            # Аналогично для получения URL.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((self.SERVER_IP, self.SERVER_PORT))
                except Exception as e:
                    print (f'Не удалось подключиться к серверу: {str(e)}')
                s.sendall(f'--file urls.data --query HGET url {self.count_tik}'.encode())
                url = s.recv(1024).decode()
                url = url.replace('\n', '').replace('\r', '')
                if url == "Error.":
                    print ('Error.')
                if url == "-> False":
                    url = last_url
                last_url = url
            # Аналогично для получения времени.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((self.SERVER_IP, self.SERVER_PORT))
                except Exception as e:
                    print (f'Не удалось подключиться к серверу: {str(e)}')
                s.sendall(f'--file urls.data --query HGET timestamp {self.count_tik}'.encode())
                timestamp = s.recv(1024).decode()
                timestamp = timestamp.replace('\n', '').replace('\r', '')
                if timestamp == "Error.":
                    print ('Error.')
                if timestamp == "-> False":
                    break
            # Обновление словарей статистики данными.
            if url not in self.statistics1:
                self.statistics1[url] = []
            self.statistics1[url].append((ip, timestamp))
            if url not in self.statistics2:
                self.statistics2[url] = []
            self.statistics2[url].append((timestamp, ip))
            if ip not in self.statistics3:
                self.statistics3[ip] = []
            self.statistics3[ip].append((url, timestamp))
            if ip not in self.statistics4:
                self.statistics4[ip] = []
            self.statistics4[ip].append((timestamp, url))
            if timestamp not in self.statistics5:
                self.statistics5[timestamp] = []
            self.statistics5[timestamp].append((ip, url))
            if timestamp not in self.statistics6:
                self.statistics6[timestamp] = []
            self.statistics6[timestamp].append((url, ip))

    # Метод для отправки статистики на сервер.
    def post_statistics(self, ip, url, timestamp):
        self.load()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.SERVER_IP, self.SERVER_PORT))
            except Exception as e:
                return f'Не удалось подключиться к серверу: {str(e)}', 500
            s.sendall(f'--file urls.data --query HSET ip {ip} {self.count_tik}'.encode())
            if s.recv(1024).decode().replace('\n', '').replace('\r', '') == "Error.":
                return 'Error.', 500
            s.close()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.SERVER_IP, self.SERVER_PORT))
            except Exception as e:
                return f'Не удалось подключиться к серверу: {str(e)}', 500
            s.sendall(f'--file urls.data --query HSET url {url} {self.count_tik}'.encode())
            if s.recv(1024).decode().replace('\n', '').replace('\r', '') == "Error.":
                return 'Error.', 500
            s.close()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.SERVER_IP, self.SERVER_PORT))
            except Exception as e:
                return f'Не удалось подключиться к серверу: {str(e)}', 500
            s.sendall(f'--file urls.data --query HSET timestamp {timestamp} {self.count_tik}'.encode())
            if s.recv(1024).decode().replace('\n', '').replace('\r', '') == "Error.":
                return 'Error.', 500
            s.close()
        if url not in self.statistics1:
            self.statistics1[url] = []
        self.statistics1[url].append((ip, timestamp))
        if url not in self.statistics2:
            self.statistics2[url] = []
        self.statistics2[url].append((timestamp, ip))
        if ip not in self.statistics3:
            self.statistics3[ip] = []
        self.statistics3[ip].append((url, timestamp))
        if ip not in self.statistics4:
            self.statistics4[ip] = []
        self.statistics4[ip].append((timestamp, url))
        if timestamp not in self.statistics5:
            self.statistics5[timestamp] = []
        self.statistics5[timestamp].append((ip, url))
        if timestamp not in self.statistics6:
            self.statistics6[timestamp] = []
        self.statistics6[timestamp].append((url, ip))
        return '', 204

    # Метод для создания отчета по заданным параметрам.
    def report(self, dimensions):
        self.load()
        report = []
        id = 1
        if len(dimensions) == 1:
            dimension = dimensions[0]
            if dimension == 'URL':
                for url, stats in self.statistics1.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': url,
                        'SourceIP': None,
                        'TimeInterval': None,
                        'Count': len(stats)
                    })
                    id += 1
            elif dimension == 'SourceIP':
                for ip, stats in self.statistics3.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': ip,
                        'TimeInterval': None,
                        'Count': len(stats)
                    })
                    id += 1
            elif dimension == 'TimeInterval':
                for timestamp, stats in self.statistics5.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': None,
                        'TimeInterval': str(timestamp),
                        'Count': len(stats)
                    })
        else:
            if (dimensions[0]=='URL' and dimensions[1]=='SourceIP'):
                for url, stats in self.statistics1.items():
                    url_dict = {}
                    for stat in stats:
                        ip, timestamp = stat
                        if ip not in url_dict:
                            url_dict[ip] = {'count': 1, 'timestamps': {timestamp: 1}}
                        else:
                            if timestamp not in url_dict[ip]['timestamps']:
                                url_dict[ip]['timestamps'][timestamp] = 1
                            else:
                                url_dict[ip]['timestamps'][timestamp] += 1
                    total_count = sum(sum(data['timestamps'].values()) for data in url_dict.values())
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': url,
                        'SourceIP': None,
                        'TimeInterval': None,
                        'Count': total_count
                    })
                    id += 1
                    for ip, data in url_dict.items():
                        if 'SourceIP' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': None,
                                'SourceIP': ip,
                                'TimeInterval': None,
                                'Count': sum(data['timestamps'].values())
                            })
                            id += 1
                        for timestamp, timestamp_count in data['timestamps'].items():
                            if 'TimeInterval' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': None,
                                    'SourceIP': None,
                                    'TimeInterval': str(timestamp),
                                    'Count': timestamp_count
                                })
                                id += 1
            if (dimensions[0]=='URL' and dimensions[1]=='TimeInterval'):
                for url, stats in self.statistics2.items():
                    url_dict = {}
                    for stat in stats:
                        timestamp, ip = stat
                        if timestamp not in url_dict:
                            url_dict[timestamp] = {'count': 1, 'ips': {ip: 1}}
                        else:
                            if ip not in url_dict[timestamp]['ips']:
                                url_dict[timestamp]['ips'][ip] = 1
                            else:
                                url_dict[timestamp]['ips'][ip] += 1
                    total_count = sum(sum(data['ips'].values()) for data in url_dict.values())
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': url,
                        'SourceIP': None,
                        'TimeInterval': None,
                        'Count': total_count
                    })
                    id += 1
                    for timestamp, data in url_dict.items():
                        if 'TimeInterval' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': None,
                                'SourceIP': None,
                                'TimeInterval': str(timestamp),
                                'Count': sum(data['ips'].values())
                            })
                            id += 1
                        for ip, ip_count in data['ips'].items():
                            if 'SourceIP' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': None,
                                    'SourceIP': ip,
                                    'TimeInterval': None,
                                    'Count': ip_count
                                })
                                id += 1
            if (dimensions[0]=='SourceIP' and dimensions[1]=='URL'):
                for ip, stats in self.statistics3.items():
                    ip_dict = {}
                    for stat in stats:
                        url, timestamp = stat
                        if url not in ip_dict:
                            ip_dict[url] = {'count': 1, 'timestamps': {timestamp: 1}}
                        else:
                            if timestamp not in ip_dict[url]['timestamps']:
                                ip_dict[url]['timestamps'][timestamp] = 1
                            else:
                                ip_dict[url]['timestamps'][timestamp] += 1
                    total_count = sum(sum(data['timestamps'].values()) for data in ip_dict.values())
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': ip,
                        'TimeInterval': None,
                        'Count': total_count
                    })
                    id += 1
                    for url, data in ip_dict.items():
                        if 'URL' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': url,
                                'SourceIP': None,
                                'TimeInterval': None,
                                'Count': sum(data['timestamps'].values())
                            })
                            id += 1
                        for timestamp, timestamp_count in data['timestamps'].items():
                            if 'TimeInterval' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': None,
                                    'SourceIP': None,
                                    'TimeInterval': str(timestamp),
                                    'Count': timestamp_count
                                })
                                id += 1
            if (dimensions[0]=='SourceIP' and dimensions[1]=='TimeInterval'):
                for ip, stats in self.statistics4.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': ip,
                        'TimeInterval': None,
                        'Count': len(stats)
                    })
                    id += 1
                    timestamp_dict = {}
                    for stat in stats:
                        timestamp, url = stat
                        if timestamp not in timestamp_dict:
                            timestamp_dict[timestamp] = {'count': 1, 'urls': {url: 1}}
                        else:
                            timestamp_dict[timestamp]['count'] += 1
                            if url not in timestamp_dict[timestamp]['urls']:
                                timestamp_dict[timestamp]['urls'][url] = 1
                            else:
                                timestamp_dict[timestamp]['urls'][url] += 1
                    for timestamp, data in timestamp_dict.items():
                        if 'TimeInterval' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': None,
                                'SourceIP': None,
                                'TimeInterval': str(timestamp),
                                'Count': data['count']
                            })
                            id += 1
                        for url, url_count in data['urls'].items():
                            if 'URL' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': url,
                                    'SourceIP': None,
                                    'TimeInterval': None,
                                    'Count': url_count
                                })
                                id += 1
            if (dimensions[0]=='TimeInterval' and dimensions[1]=='SourceIP'):
                for timestamp, stats in self.statistics5.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': None,
                        'TimeInterval': str(timestamp),
                        'Count': len(stats)
                    })
                    id += 1
                    ip_dict = {}
                    for stat in stats:
                        ip, url = stat
                        if ip not in ip_dict:
                            ip_dict[ip] = {'count': 1, 'urls': {url: 1}}
                        else:
                            if url not in ip_dict[ip]['urls']:
                                ip_dict[ip]['count'] += 1
                                ip_dict[ip]['urls'][url] = 1
                            else:
                                ip_dict[ip]['urls'][url] += 1
                    for ip, data in ip_dict.items():
                        if 'SourceIP' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': None,
                                'SourceIP': ip,
                                'TimeInterval': None,
                                'Count': sum(data['urls'].values())
                            })
                            id += 1
                        for url, url_count in data['urls'].items():
                            if 'URL' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': url,
                                    'SourceIP': None,
                                    'TimeInterval': None,
                                    'Count': url_count
                                })
                                id += 1
            if (dimensions[0]=='TimeInterval' and dimensions[1]=='URL'):
                for timestamp, stats in self.statistics6.items():
                    report.append({
                        'Id': id,
                        'Pid': None,
                        'URL': None,
                        'SourceIP': None,
                        'TimeInterval': str(timestamp),
                        'Count': len(stats)
                    })
                    id += 1
                    url_dict = {}
                    for stat in stats:
                        url, ip = stat
                        if url not in url_dict:
                            url_dict[url] = {'count': 1, 'ips': {ip: 1}}
                        else:
                            if ip not in url_dict[url]['ips']:
                                url_dict[url]['ips'][ip] = 1
                            else:
                                url_dict[url]['ips'][ip] += 1
                            url_dict[url]['count'] = sum(url_dict[url]['ips'].values())
                    for url, data in url_dict.items():
                        if 'URL' in dimensions:
                            report.append({
                                'Id': id,
                                'Pid': 1,
                                'URL': url,
                                'SourceIP': None,
                                'TimeInterval': None,
                                'Count': data['count']
                            })
                            id += 1
                        for ip, ip_count in data['ips'].items():
                            if 'SourceIP' in dimensions:
                                report.append({
                                    'Id': id,
                                    'Pid': 2,
                                    'URL': None,
                                    'SourceIP': ip,
                                    'TimeInterval': None,
                                    'Count': ip_count
                                })
                                id += 1
        # Форматирование и возврат отчета.
        formatted_report = self.format_report(report, dimensions)
        return formatted_report

    # Метод для форматирования отчета.
    def format_report(self, report, dimensions):
        max_length = max(len(item['URL']) for item in report if item['URL']) if 'URL' in dimensions else 0
        max_length = max(max_length, max(len(item['SourceIP']) for item in report if item['SourceIP'])) if 'SourceIP' in dimensions else max_length
        max_length = max(max_length, max(len(item['TimeInterval']) for item in report if item['TimeInterval'])) if 'TimeInterval' in dimensions else max_length
        formatted_report = ["\t\tДетализация".ljust(max_length) + "Количество переходов"]
        for item in report:
            line = "\t" * item['Pid'] if item['Pid'] is not None else ""
            for dimension in dimensions:
                if dimension == 'URL' and item['URL']:
                    line += f"{item['URL'].ljust(max_length)}\t"
                elif dimension == 'SourceIP' and item['SourceIP']:
                    line += f"{item['SourceIP'].ljust(max_length)}\t"
                elif dimension == 'TimeInterval' and item['TimeInterval']:
                    line += f"{item['TimeInterval'].ljust(max_length)}\t"
            if item['Pid'] == None:
                line += "\t" * 2
            elif item['Pid'] == 1:
                line += "\t" * 1
            elif item['Pid'] == 2:
                line += ""
            line += f"{item['Count']}"
            formatted_report.append(line)
        # Возврат отформатированного отчета в виде предварительно отформатированного текста.
        return '<pre>' + '\n'.join(formatted_report) + '</pre>'

# Создание экземпляра Flask-приложения.
app = Flask(__name__)
stats = Statistics() # Создание экземпляра класса Statistics.

# Маршрут для обработки POST-запросов на отправку статистики.
@app.route('/', methods=['POST'])
def post_statistics():
    # Получение данных из запроса.
    ip = request.json['ip']
    url = request.json['url']
    timestamp = request.json['timestamp']
    # Вызов метода для отправки статистики и возврат результата.
    return stats.post_statistics(ip, url, timestamp)

# Маршрут для обработки POST-запросов на создание отчета.
@app.route('/report', methods=['POST'])
def report():
    # Получение параметров из запроса.
    dimensions = request.json['Dimensions']
    # Вызов метода для создания отчета и возврат результата в формате JSON.
    return jsonify(stats.report(dimensions))

# Маршрут для обработки GET-запросов на получение отчета.
@app.route('/get_report', methods=['GET'])
def get_report():
    # Получение параметров из строки запроса.
    dimensions = request.args.get('dimensions').split(',')
    # Отправка POST-запроса на локальный сервер для получения отчета.
    response = requests.post('http://localhost:5001/report', json={"Dimensions": dimensions})
    # Возврат полученного отчета в формате JSON.
    return response.json()

if __name__ == '__main__':
    app.run(port=5001, debug=True)
