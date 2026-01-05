"""Init file for data module."""

from .schema import (
    VulnerabilityType,
    SeverityLevel, 
    VulnerabilityImpact,
    ContractSource,
    VulnerabilityLocation,
    Vulnerability,
    ContractAuditData,
    TrainingExample,
    DatasetSplit,
    DatasetProcessor,
    save_training_examples,
    load_training_examples
)

from .collectors import (
    DataCollector,
    SWCCollector,
    EthernautCollector,
    ImmuneFiCollector,
    OpenZeppelinCollector,
    SlitherCorpusCollector,
    DamnVulnerableDeFiCollector
)

# Internet-based data collectors
try:
    from .internet_collectors import (
        InternetTrainingDataCollector,
        GitHubContractCollector,
        EtherscanContractCollector,
        EnhancedSWCCollector,
        create_internet_config
    )
    HAS_INTERNET_COLLECTORS = True
except ImportError:
    HAS_INTERNET_COLLECTORS = False

__all__ = [
    # Schema classes
    "VulnerabilityType",
    "SeverityLevel",
    "VulnerabilityImpact", 
    "ContractSource",
    "VulnerabilityLocation",
    "Vulnerability",
    "ContractAuditData",
    "TrainingExample",
    "DatasetSplit",
    "DatasetProcessor",
    "save_training_examples",
    "load_training_examples",
    
    # Collectors
    "DataCollector",
    "SWCCollector",
    "EthernautCollector", 
    "ImmuneFiCollector",
    "OpenZeppelinCollector",
    "SlitherCorpusCollector",
    "DamnVulnerableDeFiCollector"
]

# Add internet collectors if available
if HAS_INTERNET_COLLECTORS:
    __all__.extend([
        "InternetTrainingDataCollector",
        "GitHubContractCollector", 
        "EtherscanContractCollector",
        "EnhancedSWCCollector",
        "create_internet_config"
    ])