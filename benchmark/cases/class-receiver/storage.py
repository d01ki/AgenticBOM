import shutil

import boto3


class Storage:
    def __init__(self) -> None:
        self.s3 = boto3.client("s3")

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket="exports", Key=key)

    def purge(self, path: str) -> None:
        self._wipe(path)

    def _wipe(self, path: str) -> None:
        shutil.rmtree(path)
