/*
  Warnings:

  - A unique constraint covering the columns `[urlToken]` on the table `VerificationCode` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "VerificationCode" ADD COLUMN     "urlToken" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "VerificationCode_urlToken_key" ON "VerificationCode"("urlToken");

-- CreateIndex
CREATE INDEX "VerificationCode_urlToken_idx" ON "VerificationCode"("urlToken");
