from abc import ABC, abstractmethod


class TargetReaderInterface(ABC):
    """Interfaz abstracta que define la lectura de la lista de targets de auditoría."""

    @abstractmethod
    def read_targets(self) -> list[str]:
        """Lee y retorna la lista de targets (IPs o dominios).

        Returns:
            List[str]: Lista de strings que representan los targets.
        """
        pass
