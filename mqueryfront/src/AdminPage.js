import React, {Component} from 'react';
import BackendStatus from './BackendStatus';
import SearchJobs from './SearchJobs';


class AdminPage extends Component {
    render() {
        return (
            <div className="container-fluid">
                <h1 className="text-center mq-bottom">dashboard</h1>
                <div className="row">
                    <div className="col-md-6">
                        <h2 className="text-center mq-bottom">backend</h2>
                        <BackendStatus />

                        <form action="/admin/index" method="POST">
                            <input type="hidden" name="path" value="/mnt/samples"/>
                            <button type="submit" className="btn btn-primary">Index /mnt/samples</button>
                        </form>

                    </div>
                    <div className="col-md-6">
                        <form action="/admin" method="post">
                            <h2 className="text-center mq-bottom">jobs/queries</h2>
                            <SearchJobs />
                        </form>
                    </div>
                </div>
            </div>
        );
    }
}

export default AdminPage;
