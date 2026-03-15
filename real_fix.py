path = r'D:\Github项目\PyAegis\pyaegis\cli.py'
with open(path, 'rb') as f:
    content = f.read()

# The exact format: 4 spaces before ), then blank line, then 4 spaces before rules_path
# Looking at bytes: '    )\r\n\r\n    rules_path...'
old_bytes = b'keys=["rules", "format", "workers", "timeout", "severity"],\r\n    )\r\n\r\n    rules_path = args.rules or _default_rules_path()'

new_bytes = b'''keys=["rules", "ruleset", "format", "workers", "timeout", "severity"],\r
    )\r
\r
    # Determine rules path: --rules takes precedence over --ruleset\r
    rules_path = None\r
    if args.rules:\r
        rules_path = args.rules\r
    elif getattr(args, "ruleset", None):\r
        rules_path = _resolve_ruleset(args.ruleset)\r
        if not rules_path:\r
            available = ", ".join(sorted(_available_rulesets().keys()))\r
            sys.stderr.write(\r
                f"Unknown ruleset: {args.ruleset}. Available rulesets: {available}\\n"\r
            )\r
            return 2\r
\r
    if not rules_path:\r
        rules_path = _default_rules_path()'''

if old_bytes in content:
    content = content.replace(old_bytes, new_bytes)
    with open(path, 'wb') as f:
        f.write(content)
    print('SUCCESS')
else:
    print('OLD BYTES NOT FOUND')
