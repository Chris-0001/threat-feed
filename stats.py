import matplotlib.pyplot as plt
from pathlib import Path
import json

def generate_graphs(dates, items_scanned, error_counts):
    plt.xkcd() # Enables the hand-drawn comic style
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    
    # Graph 1: Items Scanned
    ax1.plot(dates, items_scanned, label="Items Gathered", color="#0b4f9c", linewidth=2)
    ax1.set_title("Feed Items Gathered (Last 30 Days)")
    ax1.set_ylabel("Count")
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.tick_params(axis='x', rotation=45)
    
    # Graph 2: Errors
    ax2.bar(dates, error_counts, color="#c4271b", label="API/System Errors")
    ax2.set_title("Errors Encountered")
    ax2.set_ylabel("Error Count")
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    ax2.tick_params(axis='x', rotation=45)

    plt.tight_layout()
    # Save directly to the static site folder
    Path("_site/assets").mkdir(parents=True, exist_ok=True)
    plt.savefig("_site/assets/stats.svg", format="svg")