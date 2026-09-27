import json
import string

import password_generator
import pytest


def _isolated_config(monkeypatch, tmp_path):
    monkeypatch.setattr(password_generator, "PRIVATE_CONFIG_PATH", str(tmp_path / "private_config.json"))
    monkeypatch.setattr(password_generator, "PUBLIC_CONFIG_PATH", str(tmp_path / "public_config.json"))


def _large_word_list():
    return [f"word{first}{second}" for first in string.ascii_lowercase[:16]
            for second in string.ascii_lowercase[:16]]


def test_scrambled_generator_has_requested_shape(monkeypatch):
    settings = {
        "letters_count": 20,
        "numbers_count": 4,
        "symbols_count": 3,
    }
    result = password_generator._generate_scrambled(settings)

    assert len(result) == 27
    assert sum(character in string.ascii_letters for character in result) == 20
    assert sum(character.isdigit() for character in result) == 4
    assert sum(character in string.punctuation for character in result) == 3


def test_get_password_settings_defaults_include_reminder_days():
    settings = password_generator.get_password_settings()

    assert "reminder_days" in settings
    assert settings["reminder_days"] in (30, 60, 90, "off")


def test_update_password_settings_accepts_off_for_reminders(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    saved = password_generator.update_password_settings({"reminder_days": "off"})

    assert saved["reminder_days"] == "off"


def test_one_letter_scrambled_setting_is_rejected_before_save(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="scrambled|letters|randomness"):
        password_generator.update_password_settings({
            "format": "scrambled", "letters_count": 1,
            "numbers_count": 0, "symbols_count": 0,
        })

    assert not (tmp_path / "private_config.json").exists()


@pytest.mark.parametrize("key", ["word_count", "numbers_count", "symbols_count", "letters_count"])
def test_pathological_count_is_rejected_before_save(tmp_path, monkeypatch, key):
    _isolated_config(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="count|maximum|limit"):
        password_generator.update_password_settings({key: 10**9})

    assert not (tmp_path / "private_config.json").exists()


def test_scrambled_default_works_without_word_list(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    monkeypatch.setattr(password_generator, "load_word_list", lambda: pytest.fail("word list was loaded"))

    result = password_generator.generate_password()

    assert len(result) == 15
    assert sum(character in string.ascii_letters for character in result) == 12
    assert sum(character in string.digits for character in result) == 2
    assert sum(character in string.punctuation for character in result) == 1


@pytest.mark.parametrize("format_name", ["word_symbol_word_numbers", "word_number_chunks"])
@pytest.mark.parametrize("symbol_count", [0, 1, 3, 9])
def test_word_formats_honor_counts(tmp_path, monkeypatch, format_name, symbol_count):
    _isolated_config(monkeypatch, tmp_path)
    monkeypatch.setattr(password_generator, "load_word_list", _large_word_list)
    password_generator.update_password_settings({
        "format": format_name, "word_count": 8,
        "numbers_count": 4, "symbols_count": symbol_count,
    })

    result = password_generator.generate_password()

    assert sum(character in string.digits for character in result) == 4
    assert sum(character in string.punctuation for character in result) == symbol_count
    assert result.lower().count("word") == 8


def test_weak_word_settings_are_rejected(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    monkeypatch.setattr(password_generator, "load_word_list", lambda: ["red", "blue"])

    with pytest.raises(ValueError, match="randomness|weak"):
        password_generator.update_password_settings({
            "format": "word_number_chunks", "word_count": 2,
            "numbers_count": 0, "symbols_count": 0,
        })


def test_case_colliding_words_do_not_inflate_randomness(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    monkeypatch.setattr(password_generator, "load_word_list", lambda: ["red", "RED"])

    with pytest.raises(ValueError, match="unique"):
        password_generator.update_password_settings({
            "format": "word_symbol_word_numbers", "word_count": 16,
            "numbers_count": 0, "symbols_count": 0,
        })


@pytest.mark.parametrize("format_name", ["word_symbol_word_numbers", "word_number_chunks"])
def test_ambiguous_a_prefix_pool_cannot_claim_64_bits(tmp_path, monkeypatch, format_name):
    _isolated_config(monkeypatch, tmp_path)
    words = ["a" * length for length in range(1, 257)]
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    with pytest.raises(ValueError, match="prefix|ambiguous"):
        password_generator.update_password_settings({
            "format": format_name, "capitalize_words": False,
            "word_count": 8, "numbers_count": 0, "symbols_count": 0,
        })
    assert not (tmp_path / "private_config.json").exists()


def test_critic_pool_collapses_64_bits_of_choices_to_2041_visible_strings():
    possible_lengths = set(range(1, 257))
    for _ in range(7):
        possible_lengths = {
            prior_length + word_length
            for prior_length in possible_lengths
            for word_length in range(1, 257)
        }

    assert 256**8 == 2**64
    assert len(possible_lengths) == 2041


@pytest.mark.parametrize("format_name", ["word_symbol_word_numbers", "word_number_chunks"])
def test_mixed_length_prefix_free_pool_passes_exact_floor(tmp_path, monkeypatch, format_name):
    _isolated_config(monkeypatch, tmp_path)
    words = [
        f"a{first}{second}"
        for first in string.ascii_lowercase[:8]
        for second in string.ascii_lowercase[:16]
    ] + [
        f"bb{first}{second}"
        for first in string.ascii_lowercase[:8]
        for second in string.ascii_lowercase[:16]
    ]
    assert len(words) == 256
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    saved = password_generator.update_password_settings({
        "format": format_name, "capitalize_words": False,
        "word_count": 8, "numbers_count": 0, "symbols_count": 0,
    })

    assert saved["word_count"] == 8
    assert password_generator.generate_password().isascii()


def test_ambiguous_persisted_word_list_fails_before_generation(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    monkeypatch.setattr(
        password_generator, "load_word_list",
        lambda: ["a" * length for length in range(1, 257)],
    )
    (tmp_path / "private_config.json").write_text(
        '{"password_settings": {"format": "word_number_chunks", "word_count": 8, '
        '"numbers_count": 0, "symbols_count": 0, "capitalize_words": false}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="prefix|ambiguous"):
        password_generator.generate_password()


@pytest.mark.parametrize("capitalize_words", [False, True])
def test_rendered_case_collision_is_rejected_even_above_entropy_floor(
    tmp_path, monkeypatch, capitalize_words,
):
    _isolated_config(monkeypatch, tmp_path)
    words = _large_word_list() + ["WORDaa"]
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    with pytest.raises(ValueError, match="unique|duplicate"):
        password_generator.update_password_settings({
            "format": "word_number_chunks", "capitalize_words": capitalize_words,
            "word_count": 10, "numbers_count": 0, "symbols_count": 0,
        })


@pytest.mark.parametrize("invalid_word", ["word0", "word!", "wörd"])
def test_non_ascii_letter_word_is_rejected_before_entropy_estimate(
    tmp_path, monkeypatch, invalid_word,
):
    _isolated_config(monkeypatch, tmp_path)
    words = _large_word_list()
    words[0] = invalid_word
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    with pytest.raises(ValueError, match="ASCII|letters"):
        password_generator.update_password_settings({
            "format": "word_number_chunks", "word_count": 8,
            "numbers_count": 0, "symbols_count": 0,
        })


def test_prefix_collision_is_rejected_even_above_entropy_floor(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    words = _large_word_list() + ["wordaaa"]
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    with pytest.raises(ValueError, match="prefix|ambiguous"):
        password_generator.update_password_settings({
            "format": "word_symbol_word_numbers", "word_count": 8,
            "numbers_count": 0, "symbols_count": 0,
        })


def test_bundled_fifty_word_pool_needs_ten_words_at_default_extra_counts(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    with open(password_generator.DEFAULT_PUBLIC_WORD_LIST_PATH, encoding="utf-8") as source:
        words = json.load(source)
    assert len(words) == len(set(words)) == 50
    monkeypatch.setattr(password_generator, "load_word_list", lambda: words)

    for weak_word_count in (2, 9):
        with pytest.raises(ValueError, match="64 bits"):
            password_generator.update_password_settings({
                "format": "word_number_chunks", "word_count": weak_word_count,
                "numbers_count": 2, "symbols_count": 1,
            })

    saved = password_generator.update_password_settings({
        "format": "word_number_chunks", "word_count": 10,
        "numbers_count": 2, "symbols_count": 1,
    })
    assert saved["word_count"] == 10
    assert sum(character in string.punctuation for character in password_generator.generate_password()) == 1


def test_fractional_count_is_rejected_instead_of_truncated(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="count"):
        password_generator.update_password_settings({"symbols_count": 2.5})


def test_unsafe_persisted_settings_fail_before_generation(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    (tmp_path / "private_config.json").write_text(
        '{"password_settings": {"letters_count": 1000000000}}', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="count|maximum|limit"):
        password_generator.generate_password()


def test_persisted_one_letter_setting_fails_before_generation(tmp_path, monkeypatch):
    _isolated_config(monkeypatch, tmp_path)
    (tmp_path / "private_config.json").write_text(
        '{"password_settings": {"letters_count": 1, "numbers_count": 0, "symbols_count": 0}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="12 letters"):
        password_generator.generate_password()
