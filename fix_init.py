with open("epistemicos/__init__.py", "r") as f:
    content = f.read()

content = content.replace('    "TamperEvidentAuditTrail",\n    "VectorHygieneManager",', '    "TamperEvidentAuditTrail",\n    "AuditLogLevel",\n    "VectorHygieneManager",')

with open("epistemicos/__init__.py", "w") as f:
    f.write(content)
