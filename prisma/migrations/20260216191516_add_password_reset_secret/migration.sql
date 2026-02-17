/*
  Warnings:

  - You are about to drop the `TokenBlacklist` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "TokenBlacklist" DROP CONSTRAINT "TokenBlacklist_userId_fkey";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "passwordResetSecret" TEXT;

-- DropTable
DROP TABLE "TokenBlacklist";

-- DropEnum
DROP TYPE "TokenBlacklistType";
