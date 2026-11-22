"""Cipher-X для Android (Kivy). Формат файлов .cpx совместим с настольной версией."""
import os
import threading
import traceback

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.screenmanager import NoTransition, Screen, ScreenManager
from kivy.utils import platform

import cx_core as core

IS_ANDROID = platform == "android"
STORAGE_ROOT = "/storage/emulated/0" if IS_ANDROID else os.path.expanduser("~")

KV = """
#:set BG (0.949, 0.949, 0.941, 1)
#:set SURFACE (1, 1, 1, 1)
#:set FIELD (0.957, 0.957, 0.949, 1)
#:set BORDER (0.839, 0.839, 0.824, 1)
#:set TEXT (0.071, 0.071, 0.071, 1)
#:set MUTED (0.333, 0.333, 0.333, 1)
#:set ACCENT (0.078, 0.078, 0.078, 1)

<Label>:
    color: TEXT

<Title@Label>:
    font_size: "22sp"
    bold: True
    size_hint_y: None
    height: self.texture_size[1] + dp(4)
    text_size: self.width, None
    halign: "left"

<Hint@Label>:
    font_size: "14sp"
    color: MUTED
    size_hint_y: None
    height: self.texture_size[1] + dp(4)
    text_size: self.width, None
    halign: "left"

<Field@TextInput>:
    font_size: "16sp"
    background_normal: ""
    background_active: ""
    background_color: FIELD
    foreground_color: TEXT
    cursor_color: ACCENT
    hint_text_color: MUTED
    padding: dp(14), dp(12)

<Primary@Button>:
    font_size: "16sp"
    bold: True
    size_hint_y: None
    height: dp(52)
    background_normal: ""
    background_down: ""
    background_color: ACCENT if self.state == "normal" else (0.25, 0.25, 0.25, 1)
    color: SURFACE

<Ghost@Button>:
    font_size: "14sp"
    size_hint_y: None
    height: dp(44)
    background_normal: ""
    background_down: ""
    background_color: SURFACE if self.state == "normal" else BORDER
    color: TEXT
    canvas.after:
        Color:
            rgba: BORDER
        Line:
            rectangle: self.x, self.y, self.width, self.height

<Choice@ToggleButton>:
    font_size: "14sp"
    size_hint_y: None
    height: dp(44)
    background_normal: ""
    background_down: ""
    background_color: ACCENT if self.state == "down" else SURFACE
    color: SURFACE if self.state == "down" else TEXT
    allow_no_selection: False
    canvas.after:
        Color:
            rgba: BORDER
        Line:
            rectangle: self.x, self.y, self.width, self.height

<Tab@ToggleButton>:
    group: "tabs"
    font_size: "15sp"
    background_normal: ""
    background_down: ""
    background_color: SURFACE
    color: TEXT if self.state == "down" else MUTED
    bold: self.state == "down"
    allow_no_selection: False
    canvas.after:
        Color:
            rgba: ACCENT if self.state == "down" else SURFACE
        Rectangle:
            pos: self.x, self.top - dp(3)
            size: self.width, dp(3)

<Page@BoxLayout>:
    orientation: "vertical"
    canvas.before:
        Color:
            rgba: BG
        Rectangle:
            pos: self.pos
            size: self.size

<Column@BoxLayout>:
    orientation: "vertical"
    size_hint_y: None
    height: self.minimum_height
    padding: dp(16)
    spacing: dp(12)

<LevelPicker>:
    orientation: "vertical"
    size_hint_y: None
    height: self.minimum_height
    spacing: dp(6)
    Hint:
        text: "Уровень защиты"
    GridLayout:
        cols: 2
        spacing: dp(6)
        size_hint_y: None
        height: self.minimum_height
        Choice:
            text: "Быстрый"
            group: root.group
            on_press: root.level = 1
        Choice:
            text: "Обычный"
            group: root.group
            on_press: root.level = 2
        Choice:
            text: "Надёжный"
            group: root.group
            state: "down"
            on_press: root.level = 3
        Choice:
            text: "Максимальный"
            group: root.group
            on_press: root.level = 4

<ActivationScreen>:
    Page:
        padding: dp(24)
        spacing: dp(14)
        Widget:
        Title:
            text: "Активация Cipher-X"
        Hint:
            text: "Введите код доступа, полученный от разработчика."
        Field:
            id: code
            hint_text: "Код доступа"
            password: True
            multiline: False
            size_hint_y: None
            height: dp(52)
            on_text_validate: root.submit()
        Hint:
            id: status
            text: ""
        Primary:
            id: button
            text: "Активировать"
            on_release: root.submit()
        Widget:

<TextScreen>:
    ScrollView:
        do_scroll_x: False
        Column:
            Title:
                text: "Текст"
            Hint:
                text: "Шифруйте сообщения в Base64 — их удобно пересылать в мессенджерах."
            BoxLayout:
                size_hint_y: None
                height: dp(44)
                Choice:
                    text: "Зашифровать"
                    group: "text_mode"
                    state: "down"
                    on_press: root.mode = "encrypt"
                Choice:
                    text: "Расшифровать"
                    group: "text_mode"
                    on_press: root.mode = "decrypt"
            Field:
                id: source
                hint_text: "Введите или вставьте текст"
                size_hint_y: None
                height: dp(150)
            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)
                Ghost:
                    text: "Вставить"
                    on_release: source.text = root.paste()
                Ghost:
                    text: "Очистить"
                    on_release: source.text = ""; result.text = ""
            LevelPicker:
                id: level
                group: "text_level"
                opacity: 1 if root.mode == "encrypt" else 0
                disabled: root.mode != "encrypt"
            Field:
                id: password
                hint_text: "Пароль (минимум 8 символов)"
                password: True
                multiline: False
                size_hint_y: None
                height: dp(52)
            Primary:
                text: "Зашифровать" if root.mode == "encrypt" else "Расшифровать"
                disabled: root.busy
                on_release: root.run()
            Hint:
                id: status
                text: ""
            Field:
                id: result
                hint_text: "Здесь появится результат"
                readonly: True
                size_hint_y: None
                height: dp(150)
            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)
                Ghost:
                    text: "Копировать"
                    on_release: root.copy()
                Ghost:
                    text: "Перенести в ввод"
                    on_release: source.text = result.text; result.text = ""

<FilesScreen>:
    ScrollView:
        do_scroll_x: False
        Column:
            Title:
                text: "Файлы"
            Hint:
                text: "Фото, видео, документы любого размера. Результат сохраняется в Download/CipherX."
            BoxLayout:
                size_hint_y: None
                height: dp(44)
                Choice:
                    text: "Зашифровать"
                    group: "file_mode"
                    state: "down"
                    on_press: root.mode = "encrypt"
                Choice:
                    text: "Расшифровать"
                    group: "file_mode"
                    on_press: root.mode = "decrypt"
            Ghost:
                text: "Выбрать файл…"
                on_release: root.open_picker()
            Hint:
                text: root.selected_label
                color: (0.071, 0.071, 0.071, 1)
            LevelPicker:
                id: level
                group: "file_level"
                opacity: 1 if root.mode == "encrypt" else 0
                disabled: root.mode != "encrypt"
            Field:
                id: password
                hint_text: "Пароль (минимум 8 символов)"
                password: True
                multiline: False
                size_hint_y: None
                height: dp(52)
            Primary:
                text: "Зашифровать файл" if root.mode == "encrypt" else "Расшифровать файл"
                disabled: root.busy
                on_release: root.run()
            ProgressBar:
                max: 100
                value: root.progress
                size_hint_y: None
                height: dp(12)
            Hint:
                id: status
                text: ""

<PickerScreen>:
    Page:
        padding: dp(8)
        spacing: dp(8)
        Hint:
            text: chooser.path
            padding: dp(8), 0
        FileChooserListView:
            id: chooser
            path: root.start_path
            show_hidden: False
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            spacing: dp(8)
            Ghost:
                text: "Отмена"
                height: dp(52)
                on_release: root.cancel()
            Primary:
                text: "Выбрать"
                on_release: root.choose(chooser.selection)

<Root>:
    orientation: "vertical"
    canvas.before:
        Color:
            rgba: BG
        Rectangle:
            pos: self.pos
            size: self.size
    ScreenManager:
        id: sm
    BoxLayout:
        id: tabs
        size_hint_y: None
        height: dp(56)
        Tab:
            text: "Текст"
            state: "down"
            on_press: app.go("text")
        Tab:
            text: "Файлы"
            on_press: app.go("files")
        Tab:
            text: "Инфо"
            on_press: app.go("about")

<AboutScreen>:
    ScrollView:
        do_scroll_x: False
        Column:
            Title:
                text: "Cipher-X"
            Hint:
                text: "Версия 2.1 для Android  ·  DarkMoulder"
            Hint:
                color: (0.071, 0.071, 0.071, 1)
                text: root.about_text
"""

ABOUT_TEXT = (
    "Ключ получается из пароля через scrypt, данные шифруются AES-256-GCM "
    "блоками по 1 МиБ. Любое изменение файла или неверный пароль обнаруживаются сразу.\n\n"
    "Файлы .cpx и зашифрованный текст совместимы с версией для компьютера.\n\n"
    "Уровни защиты: Быстрый — 16 МиБ, Обычный — 32 МиБ, Надёжный — 128 МиБ, "
    "Максимальный — 256 МиБ памяти. На слабых телефонах выбирайте уровень пониже.\n\n"
    "Данные не покидают телефон."
)


def run_in_thread(work, done, fail):
    def target():
        try:
            result = work()
        except Exception as exc:
            traceback.print_exc()
            Clock.schedule_once(lambda _dt: fail(exc))
        else:
            Clock.schedule_once(lambda _dt: done(result))
    threading.Thread(target=target, daemon=True).start()


def describe(exc):
    if isinstance(exc, core.CipherError):
        return str(exc)
    if isinstance(exc, MemoryError):
        return "Не хватает памяти — выберите уровень защиты ниже."
    if isinstance(exc, OSError):
        return f"Ошибка доступа к файлу: {exc.strerror or exc}"
    return f"Ошибка: {exc}"


def check_password(password):
    if len(password) < core.MIN_PASSWORD_LEN:
        return f"Пароль должен быть не короче {core.MIN_PASSWORD_LEN} символов."
    return None


class LevelPicker(BoxLayout):
    level = NumericProperty(3)
    group = StringProperty("level")

    @property
    def n_log2(self):
        return core.LEVELS[int(self.level)].n_log2


class ActivationScreen(Screen):
    attempts = 0

    def submit(self):
        code = self.ids.code.text.strip()
        if not code or self.ids.button.disabled:
            return
        self.ids.button.disabled = True
        self.ids.status.text = "Проверка…"
        run_in_thread(lambda: core.code_matches(code), lambda ok: self._checked(ok, code), self._failed)

    def _checked(self, ok, code):
        app = App.get_running_app()
        if ok:
            app.save_activation(code)
            app.open_main()
            return
        self.attempts += 1
        left = core.MAX_ACTIVATION_ATTEMPTS - self.attempts
        self.ids.code.text = ""
        if left <= 0:
            self.ids.status.text = "Попытки закончились. Перезапустите приложение."
            return
        self.ids.status.text = f"Неверный код. Осталось попыток: {left}"
        self.ids.button.disabled = False

    def _failed(self, exc):
        self.ids.status.text = describe(exc)
        self.ids.button.disabled = False


class TextScreen(Screen):
    mode = StringProperty("encrypt")
    busy = False

    def paste(self):
        return Clipboard.paste() or ""

    def copy(self):
        if self.ids.result.text:
            Clipboard.copy(self.ids.result.text)
            self.ids.status.text = "Скопировано в буфер обмена."

    def run(self):
        text, password = self.ids.source.text, self.ids.password.text
        if not text.strip():
            self.ids.status.text = "Введите текст."
            return
        problem = check_password(password) if self.mode == "encrypt" else None
        if problem or not password:
            self.ids.status.text = problem or "Введите пароль."
            return
        self.busy = True
        self.ids.status.text = "Выполняется…"
        if self.mode == "encrypt":
            n_log2 = self.ids.level.n_log2
            work = lambda: core.encrypt_text(text, password, n_log2)
        else:
            work = lambda: core.decrypt_text(text.strip(), password)
        run_in_thread(work, self._done, self._failed)

    def _done(self, result):
        self.busy = False
        self.ids.result.text = result
        self.ids.status.text = "Готово."

    def _failed(self, exc):
        self.busy = False
        self.ids.status.text = describe(exc)


class FilesScreen(Screen):
    mode = StringProperty("encrypt")
    selected_label = StringProperty("Файл не выбран")
    progress = NumericProperty(0)
    busy = False
    selected = None

    def open_picker(self):
        app = App.get_running_app()
        app.ensure_storage()
        app.pick_file(self._picked)

    def _picked(self, path):
        self.selected = path
        self.selected_label = os.path.basename(path) if path else "Файл не выбран"

    def _output_path(self, src):
        out_dir = os.path.join(STORAGE_ROOT, "Download", "CipherX")
        os.makedirs(out_dir, exist_ok=True)
        name = os.path.basename(src)
        if self.mode == "encrypt":
            name += core.CPX_EXT
        elif name.lower().endswith(core.CPX_EXT):
            name = name[:-len(core.CPX_EXT)]
        else:
            name += ".decrypted"
        base, ext = os.path.splitext(os.path.join(out_dir, name))
        candidate, i = base + ext, 2
        while os.path.exists(candidate):
            candidate, i = f"{base} ({i}){ext}", i + 1
        return candidate

    def run(self):
        password = self.ids.password.text
        if not self.selected:
            self.ids.status.text = "Сначала выберите файл."
            return
        problem = check_password(password) if self.mode == "encrypt" else None
        if problem or not password:
            self.ids.status.text = problem or "Введите пароль."
            return
        try:
            src, dst = self.selected, self._output_path(self.selected)
            total = max(os.path.getsize(src), 1)
        except OSError as exc:
            self.ids.status.text = describe(exc)
            return
        self.busy = True
        self.progress = 0
        self.ids.status.text = "Создаётся ключ…"

        def report(done):
            value = min(100, done * 100 / total)
            Clock.schedule_once(lambda _dt: setattr(self, "progress", value))

        if self.mode == "encrypt":
            n_log2 = self.ids.level.n_log2
            work = lambda: (core.encrypt_file(src, dst, password, n_log2, report), dst)[1]
        else:
            work = lambda: (core.decrypt_file(src, dst, password, report), dst)[1]
        run_in_thread(work, self._done, self._failed)

    def _done(self, dst):
        self.busy = False
        self.progress = 100
        self.ids.status.text = f"Готово. Сохранено:\n{dst}"

    def _failed(self, exc):
        self.busy = False
        self.progress = 0
        self.ids.status.text = describe(exc)


class PickerScreen(Screen):
    start_path = StringProperty(STORAGE_ROOT)
    callback = None

    def choose(self, selection):
        if selection and os.path.isfile(selection[0]) and self.callback:
            self.callback(selection[0])
        App.get_running_app().close_picker()

    def cancel(self):
        App.get_running_app().close_picker()


class AboutScreen(Screen):
    about_text = StringProperty(ABOUT_TEXT)


class Root(BoxLayout):
    pass


class CipherXApp(App):
    title = "Cipher-X"

    def build(self):
        Window.clearcolor = (0.949, 0.949, 0.941, 1)
        Window.softinput_mode = "below_target"
        Builder.load_string(KV)
        self.root_widget = Root()
        self.sm = self.root_widget.ids.sm
        self.sm.transition = NoTransition()
        for screen in (ActivationScreen(name="activation"), TextScreen(name="text"),
                       FilesScreen(name="files"), AboutScreen(name="about"), PickerScreen(name="picker")):
            self.sm.add_widget(screen)
        if self.is_activated():
            self.open_main()
        else:
            self._show_tabs(False)
            self.sm.current = "activation"
        return self.root_widget

    def _activation_path(self):
        return os.path.join(self.user_data_dir, "activation")

    def is_activated(self):
        try:
            with open(self._activation_path(), encoding="utf-8") as fh:
                stored = fh.read().strip()
        except OSError:
            return False
        return bool(stored) and len(stored) <= 256 and core.code_matches(stored)

    def save_activation(self, code):
        try:
            with open(self._activation_path(), "w", encoding="utf-8") as fh:
                fh.write(code)
        except OSError:
            pass

    def _show_tabs(self, visible):
        tabs = self.root_widget.ids.tabs
        tabs.height = dp(56) if visible else 0
        tabs.opacity = 1 if visible else 0
        tabs.disabled = not visible

    def open_main(self):
        self._show_tabs(True)
        self.sm.current = "text"
        self.ensure_storage()

    def go(self, name):
        self.sm.current = name

    def pick_file(self, callback):
        picker = self.sm.get_screen("picker")
        picker.callback = callback
        self._return_to = self.sm.current
        self._show_tabs(False)
        self.sm.current = "picker"

    def close_picker(self):
        self._show_tabs(True)
        self.sm.current = getattr(self, "_return_to", "files")

    def ensure_storage(self):
        if not IS_ANDROID:
            return
        try:
            from android.permissions import Permission, request_permissions
            request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
            from jnius import autoclass
            version = autoclass("android.os.Build$VERSION").SDK_INT
            environment = autoclass("android.os.Environment")
            if version >= 30 and not environment.isExternalStorageManager():
                # Android 11+: доступ ко всем файлам выдаётся только в настройках.
                intent_cls = autoclass("android.content.Intent")
                settings = autoclass("android.provider.Settings")
                uri = autoclass("android.net.Uri")
                activity = autoclass("org.kivy.android.PythonActivity").mActivity
                intent = intent_cls(settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                    uri.parse("package:" + activity.getPackageName()))
                activity.startActivity(intent)
        except Exception:
            traceback.print_exc()


if __name__ == "__main__":
    CipherXApp().run()
