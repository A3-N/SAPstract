# src/ascii_art.py 
from .ui import bold

ASCII_BANNER = """\033[94m
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[97m.dBBBBP dBBBBBBP dBBBBBb dBBBBBb     dBBBP dBBBBBBP\033[94m
     @@@@#+-     .=+*%@@@@@*:::::=@@@@@*:::::::-==+*%@@@@@@@@@@@@@@@@ \033[97m.BP                   dBP      BB\033[94m                       
     @@+              *@@@%       =@@@@+              +@@@@@@@@@@@@   \033[97m`BBBBb   dBP     dBBBBK   dBP BB   dBP      dBP\033[94m    
     @=      .::     %@@@@         +@@@+               :@@@@@@@@@@       \033[97mdBP  dBP     dBP  BB  dBP  BB  dBP      dBP\033[94m
     @      @@@@@@@@@@@@@-          %@@+     +@@@%-     +@@@@@@     \033[97mdBBBBP'  dBP     dBP  dB' dBBBBBBB dBBBBP   dBP\033[94m 
     @.       :*%@@@@@@@+     =     =@@+     +@@@@=     +@@@@      \033[97m-----------------------------------------------------\033[94m     
     @%:           =*@@#     -%=     +@+     :+++:      %@@@        \033[97mTool: SAPstract  — SAP enumeration & fuzzing toolkit\033[94m
     @@@#+           :*:     *@@      #+               #@@          \033[97mBy:   @A3-N      — github.com/A3-N/SAPstract\033[94m     
     @@@@@@@%#+.             +#*:     -+            =#@@            \033[97mCred: Bizsploit  — Mariano Nuñez Di Croce\033[94m
     @@%*@@@@@@@-                      .     +@@@@@@@@                    \033[97mMetasploit — rapid7\033[94m
     @%.                                     +@@@@@@                      \033[97mpysap      — OWASP\033[94m 
     @-                   -@@%%%@@+          +@@@@                          
     @@@#+=-. .-=@@@@@@@@@@@@@@@@@+=@@@#@@@@@@@@                    
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          \033[97mDeveloped while doing ur mom, loser\033[94m
    """

def render_banner(text: str = None):
    if not text:
        text = ASCII_BANNER
    bold(text.strip("\n"))
