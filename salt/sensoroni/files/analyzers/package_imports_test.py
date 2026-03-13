import importlib
import pytest


ANALYZERS = [
    'elasticsearch',
    'emailrep',
    'greynoise',
    'localfile',
    'malwarebazaar',
    'malwarehashregistry',
    'otx',
    'pulsedive',
    'spamhaus',
    'sublime',
    'threatfox',
    'urlhaus',
    'urlscan',
    'virustotal',
    'whoislookup',
]


@pytest.mark.parametrize('analyzer', ANALYZERS)
def test_analyzer_package_imports(analyzer):
    package = importlib.import_module(analyzer)
    module = importlib.import_module(f'{analyzer}.{analyzer}')

    assert hasattr(package, '__path__'), f'{analyzer} package missing __path__'
    assert callable(module.main), f'{analyzer}.main is not callable'
    assert callable(module.analyze), f'{analyzer}.analyze is not callable'
