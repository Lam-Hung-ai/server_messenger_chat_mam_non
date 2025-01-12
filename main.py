from fastapi import FastAPI, Request, HTTPException, status
import hmac
import requests
import hashlib
import os
from dotenv import load_dotenv

# Load biến môi trường từ file .env
load_dotenv()

app = FastAPI()

# Lấy giá trị từ biến môi trường
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
APP_SECRET = os.getenv("APP_SECRET")
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")

# Endpoint để xác minh webhook
@app.get("/webhook")
async def verify_webhook(request: Request):
    hub_mode = request.query_params.get("hub.mode")
    hub_token = request.query_params.get("hub.verify_token")
    hub_challenge = request.query_params.get("hub.challenge")

    if hub_mode == "subscribe" and hub_token == VERIFY_TOKEN:
        print("WEBHOOK_VERIFIED")
        return int(hub_challenge)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Verification failed")

# Endpoint để nhận thông báo sự kiện
@app.post("/webhook")
async def handle_webhook(request: Request):
    # body_bytes = await request.body()
    # if not verify_request_signature(request, body_bytes):
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid signature")

    data = await request.json()
    if data.get("object") == "page":
        for entry in data.get("entry", []):
            for event in entry.get("messaging", []):
                sender_id = event.get("sender", {}).get("id")
                if event.get("message"):
                    message_text = event["message"].get("text")
                    handle_message(sender_id, message_text)
                # elif event.get("postback"):
                #     payload = event["postback"].get("payload")
                #     handle_postback(sender_id, payload)

        return {"status": "EVENT_RECEIVED"}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not from a page subscription")

def verify_request_signature(request: Request, body_bytes: bytes) -> bool:
    signature = request.headers.get("x-hub-signature-256", "").split("sha256=")[-1]
    if not signature:
        print("Couldn't find 'x-hub-signature-256' in headers.")
        return False

    expected_signature = hmac.new(
        key=APP_SECRET.encode(),
        msg=body_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)

def handle_message(sender_id: str, message_text: str):
    if message_text:
        response = {"text": f'You sent: "{message_text}". Now send me an image!'}
        send_message(sender_id, response)

# def handle_postback(sender_id: str, payload: str):
#     if payload == "yes":
#         response = {"text": "Thanks!"}
#     elif payload == "no":
#         response = {"text": "Oops, try sending another image."}
#     else:
#         response = {"text": "Unknown action."}
#     send_message(sender_id, response)

def send_message(sender_id: str, message: dict):
    url = f"https://graph.facebook.com/v21.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": sender_id},
        "message": message,
    }
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"Failed to send message: {response.text}")