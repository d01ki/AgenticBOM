import { DeleteObjectCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';

export class Storage {
  private s3 = new S3Client({});

  async remove(key: string): Promise<void> {
    await this.s3.send(new DeleteObjectCommand({ Bucket: 'exports', Key: key }));
  }

  async count(): Promise<number> {
    const r = await this.s3.send(new ListObjectsV2Command({ Bucket: 'exports' }));
    return r.KeyCount ?? 0;
  }
}
