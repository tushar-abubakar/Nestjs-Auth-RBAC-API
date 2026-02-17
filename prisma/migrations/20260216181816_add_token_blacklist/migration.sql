-- CreateEnum
CREATE TYPE "TokenBlacklistType" AS ENUM ('ACCESS', 'REFRESH', 'EMAIL_VERIFICATION', 'TWO_FACTOR', 'PASSWORD_RESET', 'PASSWORD_RESET_VERIFICATION');

-- CreateTable
CREATE TABLE "token_blacklist" (
    "id" TEXT NOT NULL,
    "tokenId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenType" "TokenBlacklistType" NOT NULL,
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "token_blacklist_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "token_blacklist_tokenId_key" ON "token_blacklist"("tokenId");

-- CreateIndex
CREATE INDEX "token_blacklist_tokenId_idx" ON "token_blacklist"("tokenId");

-- CreateIndex
CREATE INDEX "token_blacklist_userId_idx" ON "token_blacklist"("userId");

-- CreateIndex
CREATE INDEX "token_blacklist_expiresAt_idx" ON "token_blacklist"("expiresAt");

-- CreateIndex
CREATE INDEX "token_blacklist_createdAt_idx" ON "token_blacklist"("createdAt");

-- AddForeignKey
ALTER TABLE "token_blacklist" ADD CONSTRAINT "token_blacklist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
