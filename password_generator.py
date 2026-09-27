import secrets
import string
import json
import os
import math
from json import JSONDecodeError

try:
    import pyperclip
except ImportError:
    pyperclip = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_CONFIG_PATH = os.path.join(BASE_DIR, "json_files", "private_config.json")
PUBLIC_CONFIG_PATH = os.path.join(BASE_DIR, "public_config.json")
DEFAULT_PRIVATE_WORD_LIST_PATH = os.path.join(BASE_DIR, "json_files", "word_list.json")
DEFAULT_PUBLIC_WORD_LIST_PATH = os.path.join(BASE_DIR, "word_list.json")
DEFAULT_PASSWORD_SETTINGS = {
    "format": "scrambled",
    "word_count": 2,
    "numbers_count": 2,
    "symbols_count": 1,
    "letters_count": 12,
    "capitalize_words": True,
    "reminder_days": 90,
}
SUPPORTED_FORMATS = {
    "word_symbol_word_numbers",
    "word_number_chunks",
    "scrambled",
}
SUPPORTED_REMINDER_DAYS = {30, 60, 90, "off"}
MIN_SCRAMBLED_LETTERS = 12
MIN_ESTIMATED_BITS = 64
MAX_WORD_COUNT = 16
MAX_CHARACTER_COUNT = 128


def _load_json_file(path):
    """Safely load a JSON file and return parsed content.

    Returns None when the file is missing, empty, unreadable, or invalid JSON.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            raw_text = file.read().strip()
            if not raw_text:
                return None
            return json.loads(raw_text)
    except (OSError, JSONDecodeError):
        return None


def _save_json_file(path, payload):
    """Persist JSON payload to disk, creating parent directories when needed."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def _get_preferred_config_for_settings():
    """Return config payload/path pair, preferring private config over public."""
    private_config = _load_json_file(PRIVATE_CONFIG_PATH)
    if isinstance(private_config, dict):
        return private_config, PRIVATE_CONFIG_PATH

    public_config = _load_json_file(PUBLIC_CONFIG_PATH)
    if isinstance(public_config, dict):
        return public_config, PUBLIC_CONFIG_PATH

    return {}, PRIVATE_CONFIG_PATH


def _coerce_positive_int(value, default_value):
    """Convert value to a positive int or return default_value on failure."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default_value
    return parsed if parsed > 0 else default_value


def _coerce_nonnegative_int(value, default_value):
    """Convert value to a non-negative int or return default_value on failure."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default_value
    return parsed if parsed >= 0 else default_value


def _normalize_reminder_days(value):
    """Normalize reminder days to one of 30, 60, 90, or 'off'."""
    if isinstance(value, str) and value.strip().lower() == "off":
        return "off"

    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_PASSWORD_SETTINGS["reminder_days"]

    if parsed in (30, 60, 90):
        return parsed
    return DEFAULT_PASSWORD_SETTINGS["reminder_days"]


def _resolve_word_list_path():
    """Resolve the word list file path from config fallbacks in priority order."""
    private_config = _load_json_file(PRIVATE_CONFIG_PATH)
    if isinstance(private_config, dict) and private_config.get("word_list_path"):
        candidate = private_config["word_list_path"]
        if not os.path.isabs(candidate):
            candidate = os.path.join(BASE_DIR, candidate)
        if os.path.exists(candidate):
            return candidate

    public_config = _load_json_file(PUBLIC_CONFIG_PATH)
    if isinstance(public_config, dict) and public_config.get("word_list_path"):
        candidate = public_config["word_list_path"]
        if not os.path.isabs(candidate):
            candidate = os.path.join(BASE_DIR, candidate)
        if os.path.exists(candidate):
            return candidate

    if os.path.exists(DEFAULT_PRIVATE_WORD_LIST_PATH):
        return DEFAULT_PRIVATE_WORD_LIST_PATH
    if os.path.exists(DEFAULT_PUBLIC_WORD_LIST_PATH):
        return DEFAULT_PUBLIC_WORD_LIST_PATH

    raise FileNotFoundError(
        "No word list source found. Expected private/public config or word_list.json files."
    )


def load_word_list():
    """Load and validate word list entries used by word-based password formats.

    Raises:
        ValueError: If the resolved file does not contain a valid list of words.
        FileNotFoundError: If no usable word list source can be resolved.
    """
    path = _resolve_word_list_path()
    payload = _load_json_file(path)

    if not isinstance(payload, list):
        raise ValueError(f"Word list file must contain a JSON array: {path}")

    words = [word for word in payload if isinstance(word, str) and word.strip()]
    if len(words) < 2:
        raise ValueError("Word list must contain at least 2 words.")
    return words


def get_password_settings():
    """Return normalized password settings merged with built-in defaults."""
    config_payload, _config_path = _get_preferred_config_for_settings()
    raw_settings = {}
    if isinstance(config_payload.get("password_settings"), dict):
        raw_settings = config_payload["password_settings"]

    settings = dict(DEFAULT_PASSWORD_SETTINGS)
    selected_format = str(raw_settings.get("format", settings["format"]))
    settings["format"] = (
        selected_format if selected_format in SUPPORTED_FORMATS else DEFAULT_PASSWORD_SETTINGS["format"]
    )
    settings["word_count"] = _coerce_positive_int(raw_settings.get("word_count"), settings["word_count"])
    settings["numbers_count"] = _coerce_nonnegative_int(
        raw_settings.get("numbers_count"), settings["numbers_count"]
    )
    settings["symbols_count"] = _coerce_nonnegative_int(
        raw_settings.get("symbols_count"), settings["symbols_count"]
    )
    settings["letters_count"] = _coerce_positive_int(raw_settings.get("letters_count"), settings["letters_count"])
    settings["capitalize_words"] = bool(raw_settings.get("capitalize_words", settings["capitalize_words"]))
    settings["reminder_days"] = _normalize_reminder_days(raw_settings.get("reminder_days", settings["reminder_days"]))
    return settings


def _bounded_count(settings, name, minimum, maximum):
    """Reject invalid or excessive counts before allocating generated characters."""
    value = settings[name]
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{name} count must be an integer from {minimum} to {maximum}.")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} count must be an integer from {minimum} to {maximum}.") from None
    if isinstance(value, str) and value.strip() != str(parsed):
        raise ValueError(f"{name} count must be an integer from {minimum} to {maximum}.")
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} count must be from {minimum} to {maximum}.")
    settings[name] = parsed


def _validate_generator_settings(settings, words=None):
    """Enforce resource limits and a conservative randomness floor."""
    _bounded_count(settings, "word_count", 1, MAX_WORD_COUNT)
    _bounded_count(settings, "numbers_count", 0, MAX_CHARACTER_COUNT)
    _bounded_count(settings, "symbols_count", 0, MAX_CHARACTER_COUNT)
    _bounded_count(settings, "letters_count", 1, MAX_CHARACTER_COUNT)

    if settings["format"] == "scrambled":
        if settings["letters_count"] < MIN_SCRAMBLED_LETTERS:
            raise ValueError(f"Scrambled passwords require at least {MIN_SCRAMBLED_LETTERS} letters.")
        return

    if settings["format"] not in SUPPORTED_FORMATS:
        raise ValueError("Unsupported password format in configuration.")
    if settings["word_count"] < 2:
        raise ValueError("Word formats require at least 2 words.")
    if words is None:
        raise ValueError("Word list is required for word formats.")

    # Count only choices that remain distinct in the visible password. ASCII
    # letters keep word tokens separate from digit and punctuation choices;
    # prefix-free tokens make concatenated word sequences unambiguous.
    rendered_words = [
        word.capitalize() if settings["capitalize_words"] else word.lower()
        for word in words
    ]
    if any(not word or any(character not in string.ascii_letters for character in word)
           for word in rendered_words):
        raise ValueError("Word list entries must render as ASCII letters only.")
    if len(set(rendered_words)) != len(rendered_words):
        raise ValueError("Word list entries must be unique after capitalization.")
    sorted_words = sorted(rendered_words)
    if any(right.startswith(left) for left, right in zip(sorted_words, sorted_words[1:])):
        raise ValueError("Word list entries must be prefix-free to avoid ambiguous passwords.")

    word_bits = math.log2(len(rendered_words))
    estimated_bits = (
        settings["word_count"] * word_bits
        + settings["numbers_count"] * math.log2(10)
        + settings["symbols_count"] * math.log2(len(string.punctuation))
    )
    if estimated_bits < MIN_ESTIMATED_BITS:
        raise ValueError(
            f"Word settings are too weak for this word list; at least {MIN_ESTIMATED_BITS} "
            "bits of estimated randomness are required."
        )


def update_password_settings(new_settings):
    """Validate and save password settings to the preferred config file.

    Args:
        new_settings: Partial or full settings dictionary to persist.

    Returns:
        dict: The final normalized settings that were saved.

    Raises:
        ValueError: If the payload type or format value is invalid.
    """
    if not isinstance(new_settings, dict):
        raise ValueError("Settings payload must be a dictionary.")

    merged = dict(get_password_settings())
    merged.update(new_settings)

    selected_format = str(merged.get("format", DEFAULT_PASSWORD_SETTINGS["format"]))
    if selected_format not in SUPPORTED_FORMATS:
        raise ValueError("Unsupported format. Choose word_symbol_word_numbers, word_number_chunks, or scrambled.")

    merged["format"] = selected_format
    merged["capitalize_words"] = bool(merged.get("capitalize_words", True))
    merged["reminder_days"] = _normalize_reminder_days(
        merged.get("reminder_days", DEFAULT_PASSWORD_SETTINGS["reminder_days"])
    )
    if merged["reminder_days"] not in SUPPORTED_REMINDER_DAYS:
        raise ValueError("Reminder setting must be 30, 60, 90, or off.")

    words = load_word_list() if selected_format != "scrambled" else None
    _validate_generator_settings(merged, words)

    config_payload, config_path = _get_preferred_config_for_settings()
    if not isinstance(config_payload, dict):
        config_payload = {}
    config_payload["password_settings"] = merged
    _save_json_file(config_path, config_payload)
    return merged


def _choose_words(words, count, capitalize_words=True):
    """Randomly select word tokens and optionally capitalize each one."""
    selected_words = [secrets.choice(words) for _ in range(count)]
    if capitalize_words:
        return [word.capitalize() for word in selected_words]
    return [word.lower() for word in selected_words]


def _generate_word_symbol_word_numbers(words, settings):
    """Generate password format: words with symbol separators and trailing numbers."""
    chosen_words = _choose_words(words, settings["word_count"], settings["capitalize_words"])
    symbols = [secrets.choice(string.punctuation) for _ in range(settings["symbols_count"])]
    numbers = [str(secrets.randbelow(10)) for _ in range(settings["numbers_count"])]

    password = chosen_words[0]
    symbol_index = 0
    for word in chosen_words[1:]:
        if symbol_index < len(symbols):
            password += symbols[symbol_index]
            symbol_index += 1
        password += word

    while symbol_index < len(symbols):
        password += symbols[symbol_index]
        symbol_index += 1

    password += "".join(numbers)
    return password


def _generate_word_number_chunks(words, settings):
    """Generate password format: each word followed by its allocated digit chunk."""
    chosen_words = _choose_words(words, settings["word_count"], settings["capitalize_words"])
    numbers_count = settings["numbers_count"]
    word_count = len(chosen_words)
    base_chunk = numbers_count // word_count
    remainder = numbers_count % word_count

    segments = []
    for index, word in enumerate(chosen_words):
        chunk_size = base_chunk + (1 if index < remainder else 0)
        digits = "".join(str(secrets.randbelow(10)) for _ in range(chunk_size))
        segments.append(word + digits)

    separators = [""] * (word_count - 1)
    for index in range(settings["symbols_count"]):
        separators[index % len(separators)] += secrets.choice(string.punctuation)
    return "".join(
        segment + (separators[index] if index < len(separators) else "")
        for index, segment in enumerate(segments)
    )


def _generate_scrambled(settings):
    """Generate randomized password from mixed letters, numbers, and symbols."""
    letters = [secrets.choice(string.ascii_letters) for _ in range(settings["letters_count"])]
    numbers = [str(secrets.randbelow(10)) for _ in range(settings["numbers_count"])]
    symbols = [secrets.choice(string.punctuation) for _ in range(settings["symbols_count"])]
    characters = letters + numbers + symbols
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)

def generate_password():
    """
    Generate a random password using persisted generator settings.

    Supported formats:
    - word_symbol_word_numbers
    - word_number_chunks
    - scrambled

    Returns:
        str: The generated password.
    """
    settings = get_password_settings()
    words = load_word_list() if settings["format"] != "scrambled" else None
    _validate_generator_settings(settings, words)

    if settings["format"] == "word_symbol_word_numbers":
        return _generate_word_symbol_word_numbers(words, settings)

    if settings["format"] == "word_number_chunks":
        return _generate_word_number_chunks(words, settings)

    if settings["format"] == "scrambled":
        return _generate_scrambled(settings)

    raise ValueError("Unsupported password format in configuration.")

def generate_and_copy_password():
    """Generate a password and copy it to the system clipboard."""
    if pyperclip is None:
        raise RuntimeError("Clipboard support is unavailable. Install pyperclip to enable copying.")
    generated_password = generate_password()
    pyperclip.copy(generated_password)
    return generated_password


if __name__ == "__main__":
    generated_password = generate_and_copy_password()
    print(f"Generated password of length {len(generated_password)} was copied to clipboard.")
