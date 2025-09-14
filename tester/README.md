# CSC458 Simple Router Tester

### Prerequisites

- Python 3
- [uv](https://github.com/astral-sh/uv) package manager
- A compiled CSC458 simple router executable

### Installation

   ```bash
   uv sync
   ```

### Usage

Run the tester with your router executable:

```bash
uv run python -m csc458_tester --router_path /path/to/your/sr --logfile sr-log.txt
```

### IP Configuration
The `IP_CONFIG` file contains network interface configurations used during testing.

### Routing Table
The `rtable` file defines the routing table entries for test scenarios.
