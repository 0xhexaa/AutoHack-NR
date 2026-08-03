from colorama import init, Fore, Style

init(autoreset=True)

class Log:
    def __init__(self, debug=True):
        self.debug_mode = debug
        
    def debug(self, message: str = ""):
        if not self.debug_mode or message:
            return

        print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")

    def info(self, message: str = ""):
        if not message:
            return

        print(f"{Fore.MAGENTA}[INFO]{Style.RESET_ALL} {message}")

    def warning(self, message: str = ""):
        if not message:
            return

        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")

    def error(self, message: str = ""):
        if not message:
            return

        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

    def success(self, message: str = ""):
        if not message:
            return

        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")