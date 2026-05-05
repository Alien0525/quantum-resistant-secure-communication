"""Utility functions for visualization, formatting, and helpers."""
import sys
import time
from typing import Optional


# ANSI Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Additional colors
    CYAN = '\033[36m'
    YELLOW = '\033[33m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'
    GRAY = '\033[90m'


def colored(text: str, color: str) -> str:
    """Return colored text."""
    return f"{color}{text}{Colors.ENDC}"


def print_header(text: str):
    """Print section header with decoration."""
    width = 80
    print()
    print(colored("=" * width, Colors.OKCYAN))
    print(colored(f"{text.center(width)}", Colors.BOLD + Colors.HEADER))
    print(colored("=" * width, Colors.OKCYAN))
    print()


def print_subheader(text: str):
    """Print subsection header."""
    print(colored(f"\n{'─' * 60}", Colors.GRAY))
    print(colored(f"  {text}", Colors.BOLD + Colors.OKBLUE))
    print(colored(f"{'─' * 60}\n", Colors.GRAY))


def print_info(text: str):
    """Print info message with icon."""
    print(colored(f"[ℹ] {text}", Colors.OKCYAN))


def print_success(text: str):
    """Print success message with icon."""
    print(colored(f"[✓] {text}", Colors.OKGREEN))


def print_warning(text: str):
    """Print warning message with icon."""
    print(colored(f"[⚠] {text}", Colors.WARNING))


def print_error(text: str):
    """Print error message with icon."""
    print(colored(f"[✗] {text}", Colors.FAIL))


def print_attack(text: str):
    """Print attack simulation message."""
    print(colored(f"[🔥] {text}", Colors.FAIL + Colors.BOLD))


def hexdump(data: bytes, prefix: str = "", max_bytes: int = 64) -> str:
    """
    Create hexdump visualization of binary data.
    
    Args:
        data: Bytes to dump
        prefix: String to prepend to each line
        max_bytes: Maximum bytes to display
        
    Returns:
        Formatted hex dump string
    """
    lines = []
    data = data[:max_bytes]
    
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        # Pad hex part if needed
        hex_part = hex_part.ljust(47)
        
        line = f"{prefix}{i:04x}  {hex_part}  |{ascii_part}|"
        lines.append(colored(line, Colors.GRAY))
    
    if len(data) == max_bytes and len(data) < len(data):
        lines.append(colored(f"{prefix}... (truncated)", Colors.GRAY))
    
    return '\n'.join(lines)


def progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', 
                 length: int = 50, fill: str = '█'):
    """
    Create terminal progress bar.
    
    Args:
        iteration: Current iteration
        total: Total iterations
        prefix: Prefix string
        suffix: Suffix string
        length: Character length of bar
        fill: Bar fill character
    """
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    
    print(f'\r{prefix} |{colored(bar, Colors.OKGREEN)}| {percent}% {suffix}', end='')
    
    if iteration == total:
        print()


def animate_encryption(message: str, duration: float = 1.0):
    """Animate encryption process."""
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    frame_idx = 0
    
    while time.time() < end_time:
        print(f'\r{colored(frames[frame_idx], Colors.OKCYAN)} Encrypting: {message[:30]}...', end='')
        frame_idx = (frame_idx + 1) % len(frames)
        time.sleep(0.1)
    
    print(f'\r{colored("✓", Colors.OKGREEN)} Encrypted: {message[:30]}...')


def print_matrix_effect(text: str, duration: float = 0.5):
    """Print text with matrix-style effect."""
    import random
    chars = '01'
    
    for _ in range(int(duration * 10)):
        scrambled = ''.join(random.choice(chars) if c != ' ' else ' ' 
                          for c in text)
        print(f'\r{colored(scrambled, Colors.OKGREEN)}', end='')
        time.sleep(0.05)
    
    print(f'\r{colored(text, Colors.OKGREEN + Colors.BOLD)}')


def print_banner():
    """Print ASCII art banner."""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     ██████╗  ██████╗  ██████╗    ███████╗███████╗ ██████╗        ║
    ║     ██╔══██╗██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔════╝        ║
    ║     ██████╔╝██║   ██║██║         ███████╗█████╗  ██║             ║
    ║     ██╔═══╝ ██║▄▄ ██║██║         ╚════██║██╔══╝  ██║             ║
    ║     ██║     ╚██████╔╝╚██████╗    ███████║███████╗╚██████╗        ║
    ║     ╚═╝      ╚══▀▀═╝  ╚═════╝    ╚══════╝╚══════╝ ╚═════╝        ║
    ║                                                                  ║
    ║         Quantum-Resistant Secure Communication System            ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(colored(banner, Colors.OKCYAN + Colors.BOLD))


def format_bytes(num_bytes: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} TB"


def format_time(milliseconds: float) -> str:
    """Format time in appropriate unit."""
    if milliseconds < 1:
        return f"{milliseconds * 1000:.2f} μs"
    elif milliseconds < 1000:
        return f"{milliseconds:.2f} ms"
    else:
        return f"{milliseconds / 1000:.2f} s"


def print_comparison_table(kyber_results: dict, mceliece_results: dict):
    """Print side-by-side comparison table."""
    print_header("Performance Comparison")
    
    metrics = [
        ("Public Key Size", 'pk_size', format_bytes),
        ("Secret Key Size", 'sk_size', format_bytes),
        ("KEM Ciphertext Size", 'ct_size', format_bytes),
        ("Key Generation Time", 'keygen_time', format_time),
        ("Encapsulation Time", 'encap_time', format_time),
        ("Decapsulation Time", 'decap_time', format_time),
        ("Total Time", 'total_time', format_time),
    ]
    
    # Header
    print(f"{'Metric':<30} {'Kyber768':<20} {'McEliece':<20} {'Winner':<15}")
    print("─" * 85)
    
    # Rows
    for name, key, formatter in metrics:
        k_val = kyber_results.get(key, 0)
        m_val = mceliece_results.get(key, 0)
        
        # Determine winner (smaller is better for size, time)
        if 'size' in key.lower():
            winner = "Kyber" if k_val < m_val else "McEliece"
        elif 'time' in key.lower():
            winner = "Kyber" if k_val < m_val else "McEliece"
        else:
            winner = "-"
        
        k_str = formatter(k_val) if formatter else f"{k_val}"
        m_str = formatter(m_val) if formatter else f"{m_val}"
        w_str = colored(f"✓ {winner}", Colors.OKGREEN)
        
        print(f"{name:<30} {k_str:<20} {m_str:<20} {w_str:<15}")
    
    print()


def clear_screen():
    """Clear terminal screen."""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def press_enter_to_continue():
    """Wait for user to press enter."""
    input(colored("\nPress ENTER to continue...", Colors.GRAY))
