package org.satochip.client.seedkeeper;

import org.satochip.io.APDUResponse;

public class SeedkeeperStatus {

    private boolean setup_done = false;
    private int nbSecrets = 0;
    private int totalMemory = 0;
    private int freeMemory = 0;
    private int nbLogsTotal = 0;
    private int nbLogsAvail = 0;
    private byte[] lastLog = new byte[7];

    public void updateStatus(APDUResponse rapdu) {
        int sw = rapdu.getSw();
        if (sw == 0x9000) {
            int offset = 0;
            byte[] data = rapdu.getData();
            setup_done = true;

            int dataLength = data.length;
            int expectedLength = 17;

            if (dataLength < expectedLength) {
                throw new RuntimeException("Wrong data length: " + dataLength + ", expected: " + expectedLength);
            }

            // Memory
            this.nbSecrets = 256 * (data[offset] & 0xFF) + (data[offset + 1] & 0xFF);
            offset += 2;
            this.totalMemory = 256 * (data[offset] & 0xFF) + (data[offset + 1] & 0xFF);
            offset += 2;
            this.freeMemory = 256 * (data[offset] & 0xFF) + (data[offset + 1] & 0xFF);
            offset += 2;

            // Logs
            this.nbLogsTotal = 256 * (data[offset] & 0xFF) + (data[offset + 1] & 0xFF);
            offset += 2;
            this.nbLogsAvail = 256 * (data[offset] & 0xFF) + (data[offset + 1] & 0xFF);
            offset += 2;
            System.arraycopy(data, offset, this.lastLog, 0, 7);
        } else {
            setup_done = false;
            StatusWord statusWord = StatusWord.fromValue(sw);
            throw new RuntimeException(statusWord.getMessage());
        }
    }

    public boolean isSetupDone() {
        return setup_done;
    }

    public int getNbSecrets() {
        return nbSecrets;
    }

    public int getTotalMemory() {
        return totalMemory;
    }

    public int getFreeMemory() {
        return freeMemory;
    }

    public int getNbLogsTotal() {
        return nbLogsTotal;
    }

    public int getNbLogsAvail() {
        return nbLogsAvail;
    }

    public byte[] getLastLog() {
        return lastLog;
    }
}
