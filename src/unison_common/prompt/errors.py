class PromptEngineError(Exception):
    pass


class PromptConfigError(PromptEngineError):
    pass


class PromptSchemaError(PromptEngineError):
    pass


class PromptConflictError(PromptEngineError):
    pass


class PromptUpdateError(PromptEngineError):
    pass

