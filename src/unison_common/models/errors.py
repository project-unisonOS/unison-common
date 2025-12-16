from __future__ import annotations


class ModelPackError(RuntimeError):
    pass


class ModelPackMissingError(ModelPackError):
    pass


class ModelPackInvalidError(ModelPackError):
    pass

