package org.satochip.globalplatform;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A loadable CAP file.
 */
public class Load {
  static final byte CLA = (byte) 0x80;
  static final byte INS = (byte) 0xE8;

  static final int BLOCK_SIZE = 247; // 255 - 8 bytes for MAC

  private static String[] fileNames = {"Header", "Directory", "Import", "Applet",
      "Class", "Method", "StaticField", "Export", "ConstantPool", "RefLocation"};

  private int offset;
  private int count;
  private byte[] fullData;

  /**
   * Reads a CAP file from the given input stream.
   *
   * @param in the inpu stream
   * @throws FileNotFoundException
   * @throws IOException
   */
  public Load(InputStream in) throws FileNotFoundException, IOException {
    this.offset = 0;
    this.count = 0;
    Map<String, byte[]> files = this.loadFiles(in);
    in.close();
    this.fullData = this.getCode(files);
  }

  /**
   * Reads the components of the CAP file
   * @param in the input stream
   * @return the map of component name and values
   *
   * @throws IOException IO error
   */
  private Map<String, byte[]> loadFiles(InputStream in) throws IOException {
    Map<String, byte[]> files = new LinkedHashMap<>();
    ZipInputStream zip = new ZipInputStream(in);
    ZipEntry entry = zip.getNextEntry();

    while (entry != null) {
      ByteArrayOutputStream data = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      int count;
      while ((count = zip.read(buf)) != -1) {
        data.write(buf, 0, count);
      }
      String name = baseName(entry.getName());
      files.put(name, data.toByteArray());
      entry = zip.getNextEntry();
    }

    return files;
  }

  /**
   * The basename of the zip entry
   * @param path the path
   * @return the base name
   */
  private String baseName(String path) {
    String[] parts = path.split("[/.]");
    return parts[parts.length - 2];
  }

  /**
   * Counts the number of blocks needed to load the entire file. Keeps in account the overhead of SCP02 secure channel
   *
   * @return the block count
   */
  public int blocksCount() {
    return (int) Math.ceil(this.fullData.length / (float) BLOCK_SIZE);
  }

  /**
   * Returns the next data block
   *
   * @return the data block
   */
  public byte[] nextDataBlock() {
    if (this.offset >= this.fullData.length) {
      return null;
    }

    int rangeEnd = this.offset + BLOCK_SIZE;
    if (rangeEnd >= this.fullData.length) {
      rangeEnd = this.fullData.length;
    }

    int size = rangeEnd - offset;
    byte[] data = new byte[size];
    System.arraycopy(this.fullData, this.offset, data, 0, size);


    this.count++;
    this.offset += size;

    return data;
  }

  /**
   * True if more blocks are present, false otherwise.
   *
   * @return true if more blocks are present, false otherwise.
   */
  public boolean hasMore() {
    return this.offset < this.fullData.length;
  }

  /**
   * Encodes the length of the load TLV component
   *
   * @param length the length as integer
   * @return the length encoded as for BER-TLV
   */
  private byte[] encodeFullLength(int length) {
    if (length < 0x80) {
      return new byte[]{(byte) length};
    } else if (length < 0xFF) {
      return new byte[]{(byte) 0x81, (byte) length};
    } else if (length < 0xFFFF) {
      return new byte[]{
          (byte) 0x82,
          (byte) ((length & 0xFF00) >> 8),
          (byte) (length & 0xFF),
      };
    } else {
      return new byte[]{
          (byte) 0x83,
          (byte) ((length & 0xFF0000) >> 16),
          (byte) ((length & 0xFF00) >> 8),
          (byte) (length & 0xFF),
      };
    }
  }

  /**
   * Serializes the CAP section in a single block.
   *
   * @param files the components to serialize
   * @return the serialized load file
   *
   */
  private byte[] getCode(Map<String, byte[]> files) throws IOException {
    ByteArrayOutputStream dataStream = new ByteArrayOutputStream();

    for (String name : fileNames) {
      byte[] fileData = files.get(name);
      if (fileData == null) {
        continue;
      }

      dataStream.write(fileData);
    }

    byte[] data = dataStream.toByteArray();
    byte[] encodedFullLength = encodeFullLength(data.length);
    byte[] fullData = new byte[1 + encodedFullLength.length + data.length];

    fullData[0] = (byte) 0xC4;
    System.arraycopy(encodedFullLength, 0, fullData, 1, encodedFullLength.length);
    System.arraycopy(data, 0, fullData, 1 + encodedFullLength.length, data.length);

    return fullData;
  }

  /**
   * Returns the current block number
   *
   * @return the current block number
   */
  public int getCount() {
    return count;
  }
}
