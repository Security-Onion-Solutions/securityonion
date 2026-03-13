import importlib


def test_elasticsearch_package_imports_module():
    package = importlib.import_module('elasticsearch')
    module = importlib.import_module('elasticsearch.elasticsearch')

    assert hasattr(package, '__path__')
    assert callable(module.main)
    assert callable(module.analyze)


def test_threatfox_package_imports_module():
    package = importlib.import_module('threatfox')
    module = importlib.import_module('threatfox.threatfox')

    assert hasattr(package, '__path__')
    assert callable(module.main)
    assert callable(module.analyze)
