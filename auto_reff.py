import os
from dotenv import load_dotenv
import requests
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_typing import Address
from eth_utils import to_checksum_address
import datetime
import json
import urllib.parse
import secrets
import time
import random
from bs4 import BeautifulSoup
import re
from colorama import Fore, Back, Style, init

init()

CHECK_MARK = "\u2713"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

PROJECT_ID = "d046392f32011d37b619d321c41b107d"

def sign_eip712_message(private_key, domain, types, primary_type, message):
    full_message = {
        "types": types,
        "primaryType": primary_type,
        "domain": domain,
        "message": message
    }

    signable_message = encode_typed_data(full_message=full_message)
    account = Account.from_key(private_key)
    signed_message = Account.sign_message(signable_message, private_key=private_key)

    return signed_message.signature.hex()

def generate_new_wallet():
    account = Account.create()
    return account.address, account.key.hex()

def get_walletconnect_identity(address):
    url = f"https://rpc.walletconnect.org/v1/identity/{address}?projectId={PROJECT_ID}&sender={address}"
    headers = {"User-Agent": USER_AGENT, "Origin": "https://dashboard.synthelix.io"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_eth_balance(address, session):
  url = f"https://rpc.walletconnect.org/v1/?chainId=eip155:1&projectId={PROJECT_ID}"
  headers = {"User-Agent": USER_AGENT, "Origin": "https://dashboard.synthelix.io", "Content-Type": "text/plain"}
  data = json.dumps({"jsonrpc":"2.0","id":secrets.randbelow(100),"method":"eth_getBalance","params":[address,"latest"]})
  response = session.post(url, headers=headers, data=data)
  response.raise_for_status()
  return response.json()

def get_reverse_profile(address, session):
  url = f"https://rpc.walletconnect.org/v1/profile/reverse/{address}?sender={address}&projectId={PROJECT_ID}&apiVersion=2"
  headers = {"User-Agent": USER_AGENT, "Origin": "https://dashboard.synthelix.io"}
  response = session.get(url, headers=headers)
  response.raise_for_status()
  return response.json()

def get_csrf_token(session):
    url = "https://dashboard.synthelix.io/api/auth/csrf"
    headers = {"User-Agent": USER_AGENT, "Referer": "https://dashboard.synthelix.io"}
    response = session.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["csrfToken"]

def authenticate(session, address, signature, nonce, requestId, issuedAt, referral_code):
    url = "https://dashboard.synthelix.io/api/auth/callback/web3"
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://dashboard.synthelix.io",
        "Referer": "https://dashboard.synthelix.io/",
    }

    data = {
        "address": address,
        "signature": signature,
        "domain": '{"name":"Synthelix", "version": "1", "chainId": 1, "verifyingContract": "0x0000000000000000000000000000000000000000"}',
        "types": '{"Authentication":[{"name": "address", "type": "address"}, {"name": "statement", "type": "string"}, {"name": "nonce", "type": "string"}, {"name": "requestId", "type": "string"}, {"name": "issuedAt", "type": "string"}]}',
        "value": json.dumps({"address": address, "statement": "Sign in to enter Synthelix Dashboard.", "nonce": nonce, "requestId": requestId, "issuedAt": issuedAt}),
        "redirect": "false",
        "callbackUrl": "/",
        "csrfToken": get_csrf_token(session),
        "json": "true",
        "referralCode": referral_code,
    }

    response = session.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json(), response.headers.get('set-cookie')

def get_session(session, session_token):
  url = "https://dashboard.synthelix.io/api/auth/session"
  headers = {"User-Agent": USER_AGENT,
               "Cookie": f"__Secure-next-auth.session-token={session_token}"}
  response = session.get(url, headers=headers)
  response.raise_for_status()
  return response.json()

def get_referralsnbr(session, session_token):
    url = "https://dashboard.synthelix.io/api/get/referralsnbr"
    headers = {
        "User-Agent": USER_AGENT,
        "Cookie": f"__Secure-next-auth.session-token={session_token}"
    }
    response = session.get(url, headers=headers)
    response.raise_for_status()
    return response.json(), response.headers.get('set-cookie')

def start_node(session, session_token):
    url = "https://dashboard.synthelix.io/api/node/start"
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Cookie": f"__Secure-next-auth.session-token={session_token}"
    }
    response = session.post(url, headers=headers, data=json.dumps({}))
    response.raise_for_status()
    return response.json()

def complete_task(session, session_token, task_title, points):
    complete_task_url = "https://dashboard.synthelix.io/api/tasks/complete"
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Cookie": f"__Secure-next-auth.session-token={session_token}",
        "Referer": "https://dashboard.synthelix.io/rewards"
    }
    payload = json.dumps({"taskTitle": task_title, "points": points})
    
    try:
        response = session.post(complete_task_url, headers=headers, data=payload)
        response.raise_for_status()
        task_response = response.json()

        if task_response.get("success"):
            print(f"{Fore.GREEN}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Task '{task_title}': {CHECK_MARK}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Task '{task_title}': Gagal - {task_response.get('message')}{Style.RESET_ALL}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error: Task '{task_title}': {e}{Style.RESET_ALL}")
        return False

if __name__ == "__main__":
    #load_dotenv() #Tidak perlu lagi memuat dari .env

    referral_code = input("Masukkan kode referral: ")

    try:
        num_accounts = int(input("Masukkan jumlah akun yang ingin dibuat: "))
    except ValueError:
        print(f"{Fore.RED}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Input tidak valid. Masukkan angka.{Style.RESET_ALL}")
        exit()

    tasks_to_complete = [
        {"taskTitle": "Follow Jessie — Your AI Companion in the Synthelix Ecosystem", "points": "5000"},
        {"taskTitle": "Follow the Official Synthelix X Account", "points": "5000"},
        {"taskTitle": "Follow Hedgecast AI — Our Partner in AI Development", "points": "5000"},
    ]

    with open("success_wallet.txt", "w") as wallet_file:

      for i in range(num_accounts):
          print(f"\n{Fore.CYAN}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Membuat akun ke-{i+1}...{Style.RESET_ALL}")
          new_address, new_private_key = generate_new_wallet()
          wallet_file.write(f"address = {new_address}\nprivatekey = {new_private_key}\n---------------------------------------------------------\n")
          print(f"{Fore.BLUE}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Alamat: {new_address}{Style.RESET_ALL}")

          nonce = secrets.token_hex(16)
          requestId = str(int(time.time()))
          issuedAt = datetime.datetime.now().isoformat()

          session = requests.Session()
          session.headers.update({"User-Agent": USER_AGENT})

          domain = {
              "name": "Synthelix",
              "version": "1",
              "chainId": 1,
              "verifyingContract": "0x0000000000000000000000000000000000000000"
          }

          types = {
              "EIP712Domain": [
                  {"name": "name", "type": "string"},
                  {"name": "version", "type": "string"},
                  {"name": "chainId", "type": "uint256"},
                  {"name": "verifyingContract", "type": "address"}
              ],
              "Authentication": [
                  {"name": "address", "type": "address"},
                  {"name": "statement", "type": "string"},
                  {"name": "nonce", "type": "string"},
                  {"name": "requestId", "type": "string"},
                  {"name": "issuedAt", "type": "string"}
              ]
          }

          primary_type = "Authentication"

          message = {
              "address": new_address,
              "statement": "Sign in to enter Synthelix Dashboard.",
              "nonce": nonce,
              "requestId": requestId,
              "issuedAt": issuedAt
          }
          signature = sign_eip712_message(new_private_key, domain, types, primary_type, message)

          auth_response, auth_set_cookie_header = authenticate(session, new_address, "0x"+ signature, nonce, requestId, issuedAt, referral_code)
          print(f"{Fore.GREEN}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Auth: {CHECK_MARK}{Style.RESET_ALL}")

          if auth_set_cookie_header:
              session_token = auth_set_cookie_header.split('__Secure-next-auth.session-token=')[1].split(';')[0]
          else:
              print(f"{Fore.RED}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Gagal: Tidak dapat menemukan Session Token{Style.RESET_ALL}")
              continue

          referrals_response, referrals_set_cookie_header = get_referralsnbr(session, session_token)
          print(f"{Fore.BLUE}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Referral: {referrals_response}{Style.RESET_ALL}")

          if referrals_set_cookie_header:
              session_token = referrals_set_cookie_header.split('__Secure-next-auth.session-token=')[1].split(';')[0]
          else:
              print(f"{Fore.RED}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Gagal: Dapatkan Session Token setelah referral{Style.RESET_ALL}")
              continue

          node_response = start_node(session, session_token)
          print(f"{Fore.GREEN}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Node start: {CHECK_MARK}{Style.RESET_ALL}")
          
          for task in tasks_to_complete:
            print (f"{Fore.YELLOW}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Claim: {task['taskTitle']}{Style.RESET_ALL}")
            completed = complete_task(session, session_token, task['taskTitle'], task['points'])

          sleep_duration = random.randint(5, 15)
          print (f"{Fore.CYAN}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Jeda {sleep_duration} detik{Style.RESET_ALL}")
          time.sleep(sleep_duration)

    print(f"{Fore.GREEN}\nSelesai membuat semua akun!{Style.RESET_ALL}")