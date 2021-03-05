#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

use codec::{Decode, Encode};
use core::{convert::TryInto};
use frame_support::storage::IterableStorageMap;
use frame_support::{
    debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, traits::Get,
    storage::StorageMap, ensure,
};

use frame_system::{
    self as system, ensure_signed,
    offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer},
};
// use serde_json;
use sp_core::crypto::KeyTypeId;
use sp_runtime::offchain as rt_offchain;
use sp_runtime::{
    offchain::{http, Duration},
    transaction_validity::{
        TransactionPriority,
    },
    RuntimeDebug,
};
use sp_std::{
    prelude::*, 
    str, 
    fmt,};
// use string;

pub trait Config: system::Config + CreateSignedTransaction<Call<Self>> {
    type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
    type Call: From<Call<Self>>;
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;
}

// We use `alt_serde`, and Xanewok-modified `serde_json` so that we can compile the program
//   with serde(features `std`) and alt_serde(features `no_std`).
use alt_serde::{Deserialize, Deserializer};

// Define default proxy endpoint and API name of data proxy
pub const HTTP_REMOTE_REQUEST: &str = "http://localhost:8000/repos";
// pub const HTTP_API_NAME: &str = "getRepoContributorInfo";

pub const FETCH_TIMEOUT_PERIOD: u64 = 10_000; // in milli-seconds
pub const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"ghoc"); // Data Fetcher

pub const DEFAULT_STR: &str = "";

pub const MAX_MEMBERS: usize = 32;

// pub fn u32_to_string(number: u32) -> string::String{
//     use sp_std::fmt;
//     format!("{}", number)
// }


pub mod crypto {
    use crate::KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::app_crypto::{app_crypto, sr25519};
    use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

    app_crypto!(sr25519, KEY_TYPE);

    pub struct TestAuthId;
    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
        for TestAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}

#[serde(crate = "alt_serde")]
#[derive( Deserialize,Encode, Decode, Clone, Default, PartialEq, Eq)]
// #[cfg_attr(feature = "std", derive(Debug))]
pub struct PullRequest {
    #[serde(deserialize_with = "de_string_to_bytes")]
    owner: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    repo: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    number: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    data: Vec<u8>,
    merged: bool,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

impl fmt::Debug for PullRequest {
	// `fmt` converts the vector of bytes inside the struct back to string for
	//   more friendly display.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // core::fmt::println!("{}",self.number);
		write!(
			f,
			"{{ owner: {}, repo: {}, number: {}, merged:{}, data: {},  }}",
			str::from_utf8(&self.owner).map_err(|_| fmt::Error)?,
			str::from_utf8(&self.repo).map_err(|_| fmt::Error)?,
            str::from_utf8(&self.number).map_err(|_| fmt::Error)?,
            self.merged,
			str::from_utf8(&self.data).map_err(|_| fmt::Error)?,
		)
	}
}

// #[derive(Encode, Decode, Default, PartialEq, Eq)]
// #[cfg_attr(feature = "std", derive(Debug))]
// pub struct PullRequestInfo {
//     repo: Vec<u8>,
//     number: u32,
//     describition: Vec<u8>,
//     submitter: Vec<u8>,
//     auditor: Vec<u8>,
// }

decl_storage! {
    trait Store for Module<T: Config> as GithubOCWModule {
        
        //  RepoName get(fn repo_name): Vec<u8> = DEFAULT_STR.as_bytes().to_vec();
        //  UserName get(fn user_name): Vec<u8> = DEFAULT_STR.as_bytes().to_vec();
        //  PRNumber get(fn pr_number): u32 = 0;
        //  Period get( fn period ): u32 = 0;

        /// define the Pull Request index
        PullRequestIndex get(fn pull_request_index): u64 = 1;

         // Map key: PR number, 
        //  PullRequests get( fn pull_requests ): map hasher(blake2_128_concat) T::AccountId => PullRequest;
         PullRequests get( fn pull_requests ): map hasher(identity) u64 => PullRequest;
        //  MergedPullRequestInfos get( fn merged_pull_request_infos ): map hasher(blake2_128_concat) T::AccountId => Vec<u8>;

         // Result saves data fetched from data proxy API, which will be sent to chain with signed
         // transaction.
        //  Rslt get(fn rslt): map hasher(blake2_128_concat) Vec<u8> => (T::AccountId, Vec<u8>);
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Config>::AccountId,
    {
        ApiListUpdated(Vec<u8>),
        ApiNameUpdated(Vec<u8>),
        DataProxyUrlUpdated(Vec<u8>),
        DataUpdated(AccountId),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> {
        NoValueStored,
        InternalError,
        NetworkError,
        ApiNameError,
        ResponseFormatError,
        HttpFetchingError,
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        fn offchain_worker(block_number: T::BlockNumber) {
            debug::info!("github-ocw: Prepare to fetch data from github");
            debug::native::info!("Into github offchain workers!");

            let parent_hash = <system::Module<T>>::block_hash(block_number - (1 as u32).into());
            debug::info!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);
            // debug::info!("Current block: {:?})", block_number);
            
            // let given_repo_name_bytes = RepoName::get().clone();
            // let given_repo_name = str::from_utf8(&given_repo_name_bytes).unwrap();

            // let given_user_name_bytes = UserName::get().clone();
            // let given_user_name = str::from_utf8(&given_user_name_bytes).unwrap();
            
            // if( given_repo_name != "" && given_user_name != "" && PRNumber::get() != 0 )
            // {
                let res = Self::fetch_data_n_send_signed_tx();
                if let Err(e) = res {
                    debug::error!("Error: {:?}", e);
                }

                // RepoName::put(DEFAULT_STR.as_bytes().to_vec());
                // UserName::put(DEFAULT_STR.as_bytes().to_vec());
                // PRNumber::put(0);
             
            // }
            // Ok(())
        }

        #[weight = 10000]
        fn submit_pull_request(origin, owner: Vec<u8>, repo: Vec<u8>, pr_number: Vec<u8>) -> DispatchResult {
            debug::info!("github-ocw: Enter submit_pull_request_info");
            let who = ensure_signed(origin)?;
            debug::info!("github-ocw: Enter submit_pull_request_info: ({:?}, {:?}, {:?})", str::from_utf8(&owner).unwrap(), str::from_utf8(&repo).unwrap(), str::from_utf8(&pr_number).unwrap());
            
            let index = PullRequestIndex::get();
            <PullRequests>::insert(index, PullRequest{
                owner: owner,
                repo: repo,
                number: pr_number,
                data: DEFAULT_STR.as_bytes().to_vec(),
                merged: false,
            });
            PullRequestIndex::put(index + 1);

            // let api_name = ApiName::get();
            // Rslt::<T>::insert(&api_name, (who.clone(), api_rslt.clone()));
            Ok(())
        }

        #[weight = 10000]
        fn submit_data_signed(origin, index: u64, res: PullRequest) -> DispatchResult {
            debug::info!("github-ocw: Enter submit data singed");
            let who = ensure_signed(origin)?;
            debug::info!("github-ocw: Enter submit data singed: ({:?}, {:?})", index, res.data);
            
            ensure!(<PullRequests>::contains_key(&index), Error::<T>::NoValueStored);
            <PullRequests>::remove(&index);
            <PullRequests>::insert(index, PullRequest{
                owner: res.owner,
                repo: res.repo,
                number: res.number,
                data: res.data,
                merged: res.merged,
            });
            
            // <MergedPullRequestInfos<T>>::insert(key, res);
            // let api_name = ApiName::get();
            // Rslt::<T>::insert(&api_name, (who.clone(), api_rslt.clone()));
            Ok(())
        }

        // #[weight = 10000]
        // fn get_repo_contributor_info(origin, repo: Vec<u8>, user: Vec<u8>) -> DispatchResult {
        //     debug::info!("github-ocw: Enter get_repo_contributor_info");
        //     let who = ensure_signed(origin)?;
        //     debug::info!("github-ocw: Enter get_repo_contributor_info: ({:?}, {:?})", repo, user);

        //     RepoName::put(repo);
        //     UserName::put(user);
        //     // PRNumber::put(pr_number);

        //     // let api_name = ApiName::get();
        //     // Rslt::<T>::insert(&api_name, (who.clone(), api_rslt.clone()));
        //     Ok(())
        // }

        // #[weight = 10000]
        // fn get_repo_pulse_info(origin, repo: Vec<u8>, period: u32) -> DispatchResult {
        //     debug::info!("github-ocw: Enter get_repo_pulse_info");
        //     let who = ensure_signed(origin)?;
        //     debug::info!("github-ocw: Enter get_repo_pulse_info: ({:?}, {:?})", repo, period);

        //     RepoName::put(repo);
        //     // UserName::put(user);
        //     Period::put(period);

        //     // let api_name = ApiName::get();
        //     // Rslt::<T>::insert(&api_name, (who.clone(), api_rslt.clone()));
        //     Ok(())
        // }
    }
}

impl<T: Config> Module<T> {

    fn fetch_data_n_send_signed_tx() -> Result<(), Error<T>> {
        debug::info!("github-ocw: fetch data from github proxy");
        let signer = Signer::<T, T::AuthorityId>::all_accounts();
        if !signer.can_sign() {
            debug::error!(
                "No local accounts available. Consider adding one via `author_insertKey` RPC."
            );
            return Err(<Error<T>>::InternalError);
        }

        

        for (key, val) in <PullRequests as IterableStorageMap< u64, PullRequest>>::iter() {
            let merged = val.merged;

            debug::info!("github-ocw: index : {:?}", key);

            if merged == false 
            {
                let repo = str::from_utf8(&val.repo).unwrap();
                let pr_number = str::from_utf8(&val.number).unwrap();
                let owner = str::from_utf8(&val.owner).unwrap();

                debug::info!("github-ocw: owner:{}", owner);
                debug::info!("github-ocw: repo:{}", repo);
                debug::info!("github-ocw: pr_number:{}", pr_number);

                let resp_bytes = Self::_send_req_to_data_proxy(&owner, &repo, &pr_number)
                .map_err(|e| {
                    debug::error!("github-ocw: fetch_proxy_data error: {:?}", e);
                    <Error<T>>::NetworkError
                })?;

                let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::NetworkError)?;
		        // Print out our fetched JSON string
		        debug::info!("github-ocw: resp_str:\r\n {}", resp_str);

                // Deserializing JSON to struct, thanks to `serde` and `serde_derive`
		        // let pr_info: PullRequest =
                // serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;

                let pr_info: PullRequest =
                serde_json::from_str(&resp_str).unwrap();

                // Print out our fetched JSON string
		        debug::info!("github-ocw: PR Info:\r\n {:#?}", pr_info);

                let tx_result = signer.send_signed_transaction(|_acct| {
                    debug::info!(
                        "github-ocw: Prepare to send sign tx, signer id: {:?}",
                        _acct.id
                    );
                    Call::submit_data_signed(key.clone(), pr_info.clone())
                });

                for (acc, res) in &tx_result {
                    match res {
                        Ok(()) => {
                            debug::info!("github-ocw: [{:?}] sent API data: {:?}", acc.id, pr_info.clone())
                        }
                        Err(e) => {
                            debug::error!("github-ocw: [{:?}] Failed to submit transaction: {:?}", acc.id, e)
                        }
                    }
                }

            }
        }

        Ok(())
    }

   
    fn _send_req_to_data_proxy(
        owner: &str,
        repo: &str,
        pr_number: &str,
    ) -> Result<Vec<u8>, Error<T>> {

        debug::info!("github-ocw: send data to data proxy");
        // Get latest data proxy URL
        let data_proxy_vec = HTTP_REMOTE_REQUEST.as_bytes().to_vec();
        // let a = 5 as i32;

        // use fmt::Write;
        // let mut buf = String::new();
        // buf.write_fmt(format_args!("{}", 5))
            // .expect("a Display implementation returned an error unexpectedly");
        // let number  = 5_u32.to_string();
        //  let number = fmt::format(format_args!("{}",pr_number));
        // let number = "5";
        let data_proxy_url = [str::from_utf8(&data_proxy_vec).unwrap(), owner, repo,"pulls", pr_number ].join("/");

        // HTTP request related
        let timeout = sp_io::offchain::timestamp()
            .add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

        let pending = rt_offchain::http::Request::get(&data_proxy_url)
        .add_header("Content-Type", "application/json")
        .deadline(timeout)
        .send()
        .map_err(|e| {
            debug::error!("github-ocw: pending req error: {:?}", e);
            <Error<T>>::NetworkError
        })?;

        debug::info!("github-ocw: pending: {:?}", pending);

        let response = pending
            .try_wait(timeout)
            .map_err(|e| {
                debug::error!("github-ocw: data proxy request error: {:?}", e);
                <Error<T>>::NetworkError
            })?
            .map_err(|e| {
                debug::error!("github-ocw: data proxy request error: {:?}", e);
                <Error<T>>::NetworkError
            })?;

        debug::info!("github-ocw: response: {:?}", response);
        // debug::info!("github-ocw: response: {:?}", response.body());

        if response.code != 200 {
            debug::error!("Unexpected http request status code: {}", response.code);
            return Err(<Error<T>>::NetworkError);
        }

        Ok(response.body().collect::<Vec<u8>>())
    }

}
impl<T: Config> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
    type BlockNumber = T::BlockNumber;
    fn current_block_number() -> Self::BlockNumber {
        <frame_system::Module<T>>::block_number()
    }
}
