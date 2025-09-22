import os
import json
import time
import shutil
import base64
import subprocess
import requests
from urllib.parse import urlparse

# Отключаем предупреждения InsecureRequestWarning, т.к. verify=False для self-signed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


APP_CONFIG_FILE = os.path.join(os.getcwd(), "app_config.json")


def load_app_config(path: str) -> dict:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Не найден файл конфигурации приложения: {path}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Валидация обязательных полей
    required = ["Folder_configs", "Temp_folder", "Zip_app", "configs_to_scan"]
    for k in required:
        if k not in cfg:
            raise ValueError(f"В app_config.json отсутствует обязательный ключ: {k}")
    return cfg


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def sanitize_service_key(name: str, base_url: str) -> str:
    # Создаем ключ кэша токена на основе name + hostname сервиса, чтобы не путать разные инстансы.
    parsed = urlparse(base_url)
    host = parsed.hostname or "unknown_host"
    port = f"_{parsed.port}" if parsed.port else ""
    key = f"{name}_{host}{port}"
    # убираем потенциально недопустимые символы для имени файла
    for ch in r'\/:*?"<>| ':
        key = key.replace(ch, "_")
    return key


def token_cache_paths(temp_folder: str, service_key: str):
    tokens_dir = os.path.join(temp_folder, "tokens")
    ensure_dir(tokens_dir)
    return os.path.join(tokens_dir, f"{service_key}.json")


def read_token_cache(cache_file: str) -> dict | None:
    if not os.path.isfile(cache_file):
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return None


def write_token_cache(cache_file: str, token_data: dict):
    tmp = cache_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(token_data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, cache_file)


def decode_jwt_exp(jwt_token: str) -> int | None:
    # Возвращает значение exp (UTC epoch seconds) из JWT без проверки подписи.
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Base64URL padding
        padding = '=' * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))
        return int(payload.get("exp")) if "exp" in payload else None
    except Exception:
        return None


def is_token_valid(token_data: dict, safety_margin_sec: int = 60) -> bool:
    # Проверяем, что accessToken существует и не просрочен (с запасом в 1 минуту).
    access = token_data.get("accessToken")
    if not access:
        return False
    exp = decode_jwt_exp(access)
    if not exp:
        return False
    now = int(time.time())
    return (exp - safety_margin_sec) > now


def auth_get_token(base_url: str, login: str, password: str) -> dict:
    url = base_url.rstrip("/") + "/api/security/token"
    payload = {"login": login, "password": password}
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json-patch+json",
    }
    resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Ошибка авторизации {resp.status_code}: {resp.text}")
    data = resp.json()
    # Минимальная проверка
    if "accessToken" not in data or "refreshToken" not in data:
        raise RuntimeError(f"Некорректный ответ авторизации: {data}")
    return data


def refresh_token(base_url: str, token_data: dict) -> dict:
    url = base_url.rstrip("/") + "/api/security/token"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json-patch+json",
    }
    resp = requests.put(url, json=token_data, headers=headers, verify=False, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Ошибка продления токена {resp.status_code}: {resp.text}")
    data = resp.json()
    if "accessToken" not in data or "refreshToken" not in data:
        raise RuntimeError(f"Некорректный ответ продления токена: {data}")
    return data


def get_valid_token(base_url: str, login: str, password: str, cache_file: str) -> dict:
    # Возвращает действительный token_data, используя кэш, продление, либо новую авторизацию.
    token_data = read_token_cache(cache_file)
    if token_data and is_token_valid(token_data):
        return token_data

    if token_data:
        # попытка продлить
        try:
            new_data = refresh_token(base_url, token_data)
            if is_token_valid(new_data):
                write_token_cache(cache_file, new_data)
                return new_data
        except Exception as e:
            # Не удалось продлить, попробуем заново авторизоваться
            pass

    # новая авторизация
    new_token = auth_get_token(base_url, login, password)
    write_token_cache(cache_file, new_token)
    return new_token


def get_cluster_id(base_url: str, access_token: str) -> str:
    url = base_url.rstrip("/") + "/api/clusters"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    resp = requests.get(url, headers=headers, verify=False, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Ошибка получения clusterId {resp.status_code}: {resp.text}")
    data = resp.json()
    if not isinstance(data, list) or not data:
        raise RuntimeError(f"Пустой или некорректный список кластеров: {data}")
    # Допущение: берем первый кластер
    cluster_id = data[0].get("clusterId") or data[0].get("entityId")
    if not cluster_id:
        raise RuntimeError(f"Не найден clusterId: {data[0]}")
    return cluster_id


def download_config_zip(base_url: str, access_token: str, cluster_id: str, temp_folder: str, service_name: str) -> str:
    url = base_url.rstrip("/") + f"/api/config?clusterId={cluster_id}"
    headers = {
        "accept": "*/*",
        "Authorization": f"Bearer {access_token}",
    }
    ensure_dir(temp_folder)
    zip_path = os.path.join(temp_folder, f"{service_name}.zip")
    with requests.get(url, headers=headers, verify=False, timeout=120, stream=True) as r:
        if r.status_code != 200:
            raise RuntimeError(f"Ошибка скачивания архива {r.status_code}: {r.text}")
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    if not os.path.isfile(zip_path) or os.path.getsize(zip_path) == 0:
        raise RuntimeError("Полученный архив пуст или не сохранен.")
    return zip_path


def clean_dir(path: str):
    if os.path.isdir(path):
        # аккуратно удаляем содержимое, но не саму папку
        for entry in os.listdir(path):
            full = os.path.join(path, entry)
            if os.path.isdir(full):
                shutil.rmtree(full, ignore_errors=True)
            else:
                try:
                    os.remove(full)
                except Exception:
                    pass
    else:
        ensure_dir(path)


def extract_with_7zip(zip_app: str, archive_path: str, dest_dir: str):
    ensure_dir(dest_dir)
    # Команда: 7z x "archive" -o"dest" -y
    cmd = [zip_app, "x", archive_path, f"-o{dest_dir}", "-y"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"7-Zip завершился с ошибкой {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


def process_service(app_cfg: dict, service_cfg: dict):
    base_url = service_cfg["path"].rstrip("/")
    name = service_cfg["name"]
    login = service_cfg.get("Login") or service_cfg.get("login")
    password = service_cfg.get("Password") or service_cfg.get("password")

    if not login or not password:
        raise ValueError(f"Для сервиса '{name}' не указаны Login/Password в app_config.json")

    folder_configs = app_cfg["Folder_configs"]
    temp_folder = app_cfg["Temp_folder"]
    zip_app = app_cfg["Zip_app"]

    if not os.path.isfile(zip_app):
        raise FileNotFoundError(f"Не найден 7-Zip по пути: {zip_app}")

    ensure_dir(folder_configs)
    ensure_dir(temp_folder)

    service_key = sanitize_service_key(name, base_url)
    cache_file = token_cache_paths(temp_folder, service_key)

    print(f"[{name}] Получение действительного токена...")
    token_data = get_valid_token(base_url, login, password, cache_file)
    access_token = token_data["accessToken"]

    print(f"[{name}] Получение clusterId...")
    cluster_id = get_cluster_id(base_url, access_token)

    print(f"[{name}] Скачивание архива конфигурации...")
    archive_path = download_config_zip(base_url, access_token, cluster_id, temp_folder, service_key)

    target_dir = os.path.join(folder_configs, name)
    print(f"[{name}] Подготовка целевой папки: {target_dir}")
    ensure_dir(target_dir)
    clean_dir(target_dir)

    print(f"[{name}] Распаковка архива 7-Zip...")
    extract_with_7zip(zip_app, archive_path, target_dir)

    try:
        os.remove(archive_path)
    except Exception:
        pass

    print(f"[{name}] Готово. Конфигурация распакована в: {target_dir}")


def main():
    app_cfg = load_app_config(APP_CONFIG_FILE)
    configs = app_cfg.get("configs_to_scan", [])
    if not isinstance(configs, list) or not configs:
        print("В app_config.json не найдены записи в configs_to_scan")
        return

    # Обрабатываем только тип service
    services = [c for c in configs if c.get("type") == "service"]
    if not services:
        print("Нет конфигураций для импорта.")
        return

    for svc in services:
        name = svc.get("name", "Unknown")
        try:
            print(f"=== Обработка сервиса: {name} ===")
            process_service(app_cfg, svc)
        except Exception as e:
            print(f"[{name}] Ошибка: {e}")


if __name__ == "__main__":
    main()
