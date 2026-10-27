"""Build-time projection only. This file and Blue source stay out of Red's image."""
import json
from pathlib import Path
from catalog import CASES
from policy import red_view

if __name__=='__main__':
    Path('red_cases.json').write_text(json.dumps([red_view(case) for case in CASES]),encoding='utf-8')
