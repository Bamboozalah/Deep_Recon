
from rich.console import Console
from rich.progress import Progress
import traceback

console = Console()
shared_data = {}

MODULES = []

def register_module(module_func, name):
    MODULES.append({"func": module_func, "name": name})

def run_all_modules():
    results = {}
    with Progress(transient=True) as progress:
        task = progress.add_task("[bold cyan]Running recon modules...", total=len(MODULES))

        for mod in MODULES:
            name = mod["name"]
            func = mod["func"]
            try:
                progress.console.log(f"[cyan]Running {name}...")
                result = func(shared_data)
                results[name] = result
                progress.advance(task)
            except Exception as e:
                results[name] = {"error": str(e), "traceback": traceback.format_exc()}
                progress.console.log(f"[red]Error running {name}: {e}")
                progress.advance(task)
    return results
