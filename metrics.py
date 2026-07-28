import json

class ASTAnalyzer:
    def __init__(self):
        pass

    def passes_static_ast(self, text):
        try:
            json.loads(text.strip())
            return True
        except json.JSONDecodeError:
            return False

    def count_ast_nodes(self, text):
        return len(text) # Mock metric
