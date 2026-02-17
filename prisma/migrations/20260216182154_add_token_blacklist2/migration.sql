/*
  Warnings:

  - You are about to drop the `token_blacklist` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "token_blacklist" DROP CONSTRAINT "token_blacklist_userId_fkey";

-- DropTable
DROP TABLE "token_blacklist";

-- CreateTable
CREATE TABLE "TokenBlacklist" (
    "id" TEXT NOT NULL,
    "tokenId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenType" "TokenBlacklistType" NOT NULL,
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TokenBlacklist_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "TokenBlacklist_tokenId_key" ON "TokenBlacklist"("tokenId");

-- CreateIndex
CREATE INDEX "TokenBlacklist_tokenId_idx" ON "TokenBlacklist"("tokenId");

-- CreateIndex
CREATE INDEX "TokenBlacklist_userId_idx" ON "TokenBlacklist"("userId");

-- CreateIndex
CREATE INDEX "TokenBlacklist_expiresAt_idx" ON "TokenBlacklist"("expiresAt");

-- CreateIndex
CREATE INDEX "TokenBlacklist_createdAt_idx" ON "TokenBlacklist"("createdAt");

-- AddForeignKey
ALTER TABLE "TokenBlacklist" ADD CONSTRAINT "TokenBlacklist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
