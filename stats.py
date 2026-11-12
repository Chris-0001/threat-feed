import matplotlib.pyplot as plt
from pathlib import Path
def generate_graphs(dates, items_scanned, error_counts):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    
    # Graph 1: Items Scanned
    ax1.plot(dates, items_scanned, label="Items Gathered", color="#0b4f9c", linewidth=2)
    ax1.set_title("Feed Items Gathered by Month (Last 12 Months)")
    ax1.set_ylabel("Count")
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.tick_params(axis='x', rotation=45)
    
    # Graph 2: Errors
    ax2.bar(dates, error_counts, color="#c4271b", label="API/System Errors")
    ax2.set_title("Errors Encountered by Month")
    ax2.set_ylabel("Error Count")
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    ax2.tick_params(axis='x', rotation=45)
    ax1.tick_params(axis='x', rotation=45)

    fig.tight_layout()
    output = Path("_site/assets/stats.svg")
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, format="svg", metadata={"Date": None})
    plt.close(fig)