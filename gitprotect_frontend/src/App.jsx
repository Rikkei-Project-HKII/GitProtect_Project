import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { RepoList } from './components/RepoList';
import { AddRepoModal } from './components/AddRepoModal';
import { repoApi } from './api/repoApi';

export default function App() {
    const [repos, setRepos] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const fetchRepos = async () => {
        try {
            setIsRefreshing(true);
            const data = await repoApi.getRepos();
            setRepos(Array.isArray(data) ? data : data.repositories || []);
            setError(null);
        } catch (err) {
            setError(err.response?.data?.message || err.message || 'Lỗi kết nối API GET /api/v1/repos');
        } finally {
            setLoading(false);
            setIsRefreshing(false);
        }
    };

    useEffect(() => {
        fetchRepos();
    }, []);

    const handleConnectRepo = async (repoUrl, githubPat) => {
        return await repoApi.connectRepo(repoUrl, githubPat);
    };

    return (
        <div class="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col">
            <Navbar onRefresh={fetchRepos} isRefreshing={isRefreshing} />

            <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
                <RepoList
                    repos={repos}
                    loading={loading}
                    error={error}
                    onOpenAddModal={() => setIsModalOpen(true)}
                />
            </main>

            <AddRepoModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                onSuccess={fetchRepos}
                onConnect={handleConnectRepo}
            />
        </div>
    );
}