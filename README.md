# Contextual Spotify
A tool that changes the logged in Spotify user's currently playing playlist based on the process with most cpu usage in the running machine.
This tool is based on [process_dj.py, from InfiniteRadio](https://github.com/LaurieWired/InfiniteRadio/blob/main/process_dj.py) by @LaurieWired. The original version of the file is provided in `original_process_dj`

> [!WARNING]
> This tool requires a Spotify Premium account. I haven't tested the full functionallity for this very reason.
# Running the tool
Beacause this is a Python project, you don't need to compile anything.

0. Prerequisites:
   - Have Python installed (tested with 3.12.6)
   - Install dependencies:
     > [!TIP]
     > You can create a virtual environment if you don't want to install the dependencies globally on your machine with:
     >
     > On Windows:
     > ```bat
     > py -m venv .venv
     > ```
     > On Unix (Linux/macOS):
     > ```bash
     > python3 -m venv .venv
     > ```
     > And start it:
     > ```bat
     > .venv\Scripts\activate
     > ```
     > On Unix (Linux/macOS):
     > ```bash
     > source .venv/bin/activate
     > ```
     > And `deactivate` to deactivate

     Install both `requests` and `dotenv`:
     ```bat
     //Windows/Unix/virtual environment
     py|python3|.venv/Scripts/python -m pip install requests, dotenv
     ```
1. Run the script:
   ```bat
   //Windows/Unix/virtual environment
   py|python3|.venv/Scripts/python process_dj.py [--ip localhost] [--port 3000] [--interval 10] [--verbose]
   ```
   Argument explanation:
   - --ip: ip where you want to bind the socket for Spotify authentication (default is 127-0-0-1 or localhost)
   - --port: port to which you want to bind the socket for Spotify authentication (default is 3000)
   - --interval: number of seconds for the interval to check the top process (default 10)
   - --verbose: prints more debug information to the console
