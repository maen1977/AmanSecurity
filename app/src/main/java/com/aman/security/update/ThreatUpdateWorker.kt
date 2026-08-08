package com.aman.security.update

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.ThreatDatabaseUpdater

class ThreatUpdateWorker(appContext: Context, params: WorkerParameters) : Worker(appContext, params) {
    override fun doWork(): Result {
        return when (ThreatDatabaseUpdater(applicationContext, SignatureDatabase(applicationContext)).update()) {
            ThreatDatabaseUpdater.Result.NetworkError -> Result.retry()
            // A rejected server payload must never replace the last valid database, but it also
            // must not permanently terminate periodic update checks. Keep the valid local DB and
            // allow the next scheduled cycle to check again.
            ThreatDatabaseUpdater.Result.InvalidDatabase,
            ThreatDatabaseUpdater.Result.InvalidSignature,
            ThreatDatabaseUpdater.Result.UpToDate,
            is ThreatDatabaseUpdater.Result.Updated -> Result.success()
        }
    }
}
