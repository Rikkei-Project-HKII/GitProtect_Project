import axiosClient from './axiosClient';

export const getAuthorAudit = (repoId, page, signal) => axiosClient.get(
  `/audit/authors/${repoId}`,
  { params: { spoofing_only: true, page, page_size: 5 }, signal }
);
